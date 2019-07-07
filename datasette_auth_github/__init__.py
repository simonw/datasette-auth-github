import base64
import hashlib
import hmac
import json
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qsl

import http3

from datasette import hookimpl

SALT = "datasette-auth-github"
LOGIN_CSS = """
<style>
body {
    font-family: "Helvetica Neue", sans-serif;
    font-size: 1rem;
}</style>
"""


class BadSignature(Exception):
    pass


def ensure_bytes(s):
    if not isinstance(s, bytes):
        return s.encode("utf-8")
    else:
        return s


def salted_hmac(salt, value, secret):
    salt = ensure_bytes(salt)
    secret = ensure_bytes(secret)
    key = hashlib.sha1(salt + secret).digest()
    return hmac.new(key, msg=ensure_bytes(value), digestmod=hashlib.sha1)


class Signer:
    def __init__(self, secret):
        self.secret = secret

    def signature(self, value):
        return (
            base64.urlsafe_b64encode(salted_hmac(SALT, value, self.secret).digest())
            .strip(b"=")
            .decode()
        )

    def sign(self, value):
        return "{}:{}".format(value, self.signature(value))

    def unsign(self, signed_value):
        if ":" not in signed_value:
            raise BadSignature("No : found")
        value, signature = signed_value.rsplit(":", 1)
        if hmac.compare_digest(signature, self.signature(value)):
            return value
        raise BadSignature("Signature does not match")


async def send_html(send, html, status=200, headers=None):
    headers = headers or []
    if "content-type" not in [h.lower() for h, v in headers]:
        headers.append(["content-type", "text/html"])
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                [key.encode("utf8"), value.encode("utf8")] for key, value in headers
            ],
        }
    )
    await send({"type": "http.response.body", "body": html.encode("utf8")})


class AsgiAuth:
    cookie_name = "asgi_auth"
    logout_path = "/-/logout"
    logout_cookie_name = "asgi_auth_logout"
    cookie_ttl = None

    def __init__(self, app, cookie_secret, cookie_ttl=None):
        self.app = app
        self.cookie_secret = cookie_secret
        self.cookie_ttl = cookie_ttl

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        send = self.wrapped_send(send)
        if scope.get("path") == self.logout_path:
            headers = [["location", "/"]]
            output_cookies = SimpleCookie()
            output_cookies[self.cookie_name] = ""
            output_cookies[self.cookie_name]["path"] = "/"
            headers.append(["set-cookie", output_cookies.output(header="").lstrip()])
            output_cookies = SimpleCookie()
            output_cookies[self.logout_cookie_name] = "stay-logged-out"
            output_cookies[self.logout_cookie_name]["path"] = "/"
            headers.append(["set-cookie", output_cookies.output(header="").lstrip()])
            await send_html(send, "", 302, headers)
            return
        auth = self.auth_from_scope(scope)
        if auth:
            await self.app(dict(scope, auth=auth), receive, send)
        else:
            await self.require_auth(scope, receive, send)

    def wrapped_send(self, send):
        async def wrapped_send(event):
            # We only wrap http.response.start with headers
            if not (event["type"] == "http.response.start" and event.get("headers")):
                await send(event)
                return
            # Rebuild headers to include cache-control: private
            original_headers = event.get("headers") or []
            new_headers = [
                [key, value]
                for key, value in original_headers
                if key.lower() != b"cache-control"
            ]
            new_headers.append([b"cache-control", b"private"])
            await send({**event, **{"headers": new_headers}})

        return wrapped_send

    def cookies_from_scope(self, scope):
        cookie = dict(scope.get("headers") or {}).get(b"cookie")
        if not cookie:
            return {}
        simple_cookie = SimpleCookie()
        simple_cookie.load(cookie.decode("utf8"))
        return {key: morsel.value for key, morsel in simple_cookie.items()}

    def auth_from_scope(self, scope):
        auth_cookie = self.cookies_from_scope(scope).get(self.cookie_name)
        if not auth_cookie:
            return None
        # Decode the signed cookie
        signer = Signer(self.cookie_secret)
        try:
            cookie_value = signer.unsign(auth_cookie)
        except BadSignature:
            return None
        decoded = json.loads(cookie_value)
        # Has the cookie expired?
        if self.cookie_ttl is not None:
            if "ts" not in decoded:
                return None
            if (int(time.time()) - self.cookie_ttl) > decoded["ts"]:
                return None
        return decoded

    async def require_auth(self, scope, receive, send):
        await send_html(send, "<h1>Authentication required</h1>")


class GitHubAuth(AsgiAuth):
    callback_path = "/-/auth-callback"
    # Tests can over-ride api_client here:
    github_api_client = http3.AsyncClient()

    def __init__(
        self,
        app,
        cookie_secret,
        client_id,
        client_secret,
        cookie_ttl=24 * 60 * 60,
        disable_auto_login=False,
        allow_users=None,
        allow_orgs=None,
        allow_teams=None,
    ):
        self.app = app
        self.cookie_secret = cookie_secret
        self.client_id = client_id
        self.client_secret = client_secret
        self.cookie_ttl = cookie_ttl
        self.disable_auto_login = disable_auto_login
        self.allow_users = allow_users
        self.allow_orgs = allow_orgs
        self.allow_teams = allow_teams
        self.team_to_team_id = {}

    def oauth_scope(self):
        if self.allow_teams is not None:
            return "read:org"
        if self.allow_orgs is None:
            return "user:email"
        else:
            return "user"

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        send = self.wrapped_send(send)
        if scope.get("path") == self.callback_path:
            return await self.auth_callback(scope, receive, send)
        else:
            return await super().__call__(scope, receive, send)

    async def user_is_allowed(self, auth, access_token):
        # If no permissions set at all, user is allowed
        if (
            self.allow_users is None
            and self.allow_orgs is None
            and self.allow_teams is None
        ):
            return True
        if self.allow_users is not None:
            # Check if the user is in that list
            if auth["username"] in force_list(self.allow_users):
                return True
        if self.allow_orgs is not None:
            # For each org, check if user is a member
            for org in force_list(self.allow_orgs):
                url = "https://api.github.com/orgs/{}/memberships/{}?access_token={}".format(
                    org, auth["username"], access_token
                )
                response = await self.github_api_client.get(url)
                if response.status_code == 200 and response.json()["state"] == "active":
                    return True
        if self.allow_teams is not None:
            for team in force_list(self.allow_teams):
                if team not in self.team_to_team_id:
                    # Look up the team_id using the GitHub API
                    org_slug, _, team_slug = team.partition("/")
                    lookup_url = "https://api.github.com/orgs/{}/teams/{}?access_token={}".format(
                        org_slug, team_slug, access_token
                    )
                    response = await self.github_api_client.get(lookup_url)
                    if response.status_code == 200:
                        self.team_to_team_id[team] = response.json()["id"]
                    else:
                        return False
                team_id = self.team_to_team_id[team]
                # Check if the user is a member of this team
                team_membership_url = (
                    url
                ) = "https://api.github.com/teams/{}/memberships/{}?access_token={}".format(
                    team_id, auth["username"], access_token
                )
                response = await self.github_api_client.get(url)
                if response.status_code == 200 and response.json()["state"] == "active":
                    return True

        return False

    async def auth_callback(self, scope, receive, send):
        # Look for ?code=
        qs = dict(parse_qsl(scope["query_string"].decode("utf8")))
        if not qs.get("code"):
            await send_html(send, "Authentication failed, no code")
            return
        # Exchange that code for a token
        github_response = (
            await self.github_api_client.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": qs["code"],
                },
            )
        ).text
        parsed = dict(parse_qsl(github_response))
        # b'error=bad_verification_code&error_description=The+code+passed...'
        if parsed.get("error"):
            await send_html(
                send,
                "{}<h1>GitHub authentication error</h1><p>{}</p><p>{}</p>".format(
                    LOGIN_CSS, parsed["error"], parsed.get("error_description") or ""
                ),
            )
            return
        access_token = parsed.get("access_token")
        if not access_token:
            await send_html(send, "No valid access token")
            return
        # Use access_token to verify user
        profile_url = "https://api.github.com/user?access_token={}".format(access_token)
        try:
            profile = (await self.github_api_client.get(profile_url)).json()
        except ValueError:
            await send_html(send, "Could not load GitHub profile")
            return
        auth = {
            "id": str(profile["id"]),
            "name": profile["name"],
            "username": profile["login"],
            "email": profile["email"],
        }
        # Are they allowed?
        if not (await self.user_is_allowed(auth, access_token)):
            await send_html(
                send, """{}<h1>Access forbidden</h1>""".format(LOGIN_CSS), status=403
            )
            return

        # Set a signed cookie and redirect to homepage
        signer = Signer(self.cookie_secret)
        signed_cookie = signer.sign(
            json.dumps(dict(auth, ts=int(time.time())), separators=(",", ":"))
        )
        output_cookies = SimpleCookie()
        output_cookies[self.cookie_name] = signed_cookie
        output_cookies[self.cookie_name]["path"] = "/"
        await send_html(
            send,
            "",
            302,
            [
                ["location", "/"],
                ["set-cookie", output_cookies.output(header="").lstrip()],
            ],
        )

    async def require_auth(self, scope, receive, send):
        github_login_url = "https://github.com/login/oauth/authorize?scope={}&client_id={}".format(
            self.oauth_scope(), self.client_id
        )
        if self.disable_auto_login or self.cookies_from_scope(scope).get(
            self.logout_cookie_name
        ):
            await send_html(
                send,
                """{}<h1>Logged out</h1><p><a href="{}">Log in with GitHub</a></p>""".format(
                    LOGIN_CSS, github_login_url
                ),
            )
        else:
            await send_html(send, "", 302, [["location", github_login_url]])


def force_list(value):
    if isinstance(value, str):
        return [value]
    return value


@hookimpl
def asgi_wrapper(datasette):
    config = datasette.plugin_config("datasette-auth-github") or {}
    client_id = config.get("client_id")
    client_secret = config.get("client_secret")
    disable_auto_login = bool(config.get("disable_auto_login"))
    allow_users = config.get("allow_users")
    allow_orgs = config.get("allow_orgs")
    allow_teams = config.get("allow_teams")
    cookie_ttl = config.get("cookie_ttl") or 24 * 60 * 60
    cookie_version = config.get("cookie_version") or "default"

    def wrap_with_asgi_auth(app):
        if not (client_id and client_secret):
            return app

        cookie_secret = salted_hmac(
            "cookie_secret", client_id, client_secret + str(cookie_version)
        ).digest()

        return GitHubAuth(
            app,
            cookie_secret=cookie_secret,
            client_id=client_id,
            client_secret=client_secret,
            cookie_ttl=cookie_ttl,
            disable_auto_login=disable_auto_login,
            allow_users=allow_users,
            allow_orgs=allow_orgs,
            allow_teams=allow_teams,
        )

    return wrap_with_asgi_auth


@hookimpl
def extra_template_vars(request):
    return {"auth": request.scope.get("auth")}

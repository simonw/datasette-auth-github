import hashlib
import json
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qsl

import http3

from .utils import BadSignature, Signer, force_list, send_html, cookies_from_scope

LOGIN_CSS = """
<style>
body {
    font-family: "Helvetica Neue", sans-serif;
    font-size: 1rem;
}</style>
"""


class GitHubAuth:
    cookie_name = "asgi_auth"
    logout_cookie_name = "asgi_auth_logout"
    redirect_cookie_name = "asgi_auth_redirect"
    callback_path = "/-/auth-callback"
    logout_path = "/-/logout"
    redirect_path_blacklist = {"/favicon.ico"}
    # Tests can over-ride github_api_client_factory here:
    github_api_client_factory = http3.AsyncClient

    def __init__(
        self,
        app,
        client_id,
        client_secret,
        cookie_ttl=24 * 60 * 60,
        cookie_secret=None,
        cookie_version=None,
        disable_auto_login=False,
        allow_users=None,
        allow_orgs=None,
        allow_teams=None,
    ):
        self.app = app
        self.client_id = client_id
        self.client_secret = client_secret
        self.cookie_ttl = cookie_ttl
        self.disable_auto_login = disable_auto_login
        self.allow_users = allow_users
        self.allow_orgs = allow_orgs
        self.allow_teams = allow_teams
        self.team_to_team_id = {}

        cookie_version = cookie_version or "default"
        # Derive cookie_secret (used for signing cookies)
        self.cookie_secret = hashlib.pbkdf2_hmac(
            "sha256",
            "{}:{}:{}".format(client_id, client_secret, cookie_version).encode("utf8"),
            b"cookie_secret_salt",
            100000,
        )

    def oauth_scope(self):
        if self.allow_teams is not None:
            return "read:org"
        if self.allow_orgs is None:
            return "user:email"
        else:
            return "user"

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        send = self.wrapped_send(send)

        if scope.get("path") == self.logout_path:
            return await self.logout(scope, receive, send)

        if scope.get("path") == self.callback_path:
            return await self.auth_callback(scope, receive, send)

        auth = self.auth_from_scope(scope)
        if auth:
            await self.app(dict(scope, auth=auth), receive, send)
        else:
            await self.require_auth(scope, receive, send)

    async def logout(self, scope, receive, send):
        headers = [["location", "/"]]
        output_cookies = SimpleCookie()
        output_cookies[self.cookie_name] = ""
        output_cookies[self.cookie_name]["path"] = "/"
        output_cookies[self.cookie_name]["max-age"] = 0
        output_cookies[self.cookie_name]["expires"] = 0
        headers.append(["set-cookie", output_cookies.output(header="").lstrip()])
        output_cookies = SimpleCookie()
        output_cookies[self.logout_cookie_name] = "stay-logged-out"
        output_cookies[self.logout_cookie_name]["path"] = "/"
        headers.append(["set-cookie", output_cookies.output(header="").lstrip()])
        await send_html(send, "", 302, headers)

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

    def auth_from_scope(self, scope):
        auth_cookie = cookies_from_scope(scope).get(self.cookie_name)
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
                response = await self.github_api_client_factory().get(url)
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
                    response = await self.github_api_client_factory().get(lookup_url)
                    if response.status_code == 200:
                        self.team_to_team_id[team] = response.json()["id"]
                    else:
                        return False
                team_id = self.team_to_team_id[team]
                # Check if the user is a member of this team
                team_membership_url = "https://api.github.com/teams/{}/memberships/{}?access_token={}".format(
                    team_id, auth["username"], access_token
                )
                response = await self.github_api_client_factory().get(
                    team_membership_url
                )
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
            await self.github_api_client_factory().post(
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
            profile = (await self.github_api_client_factory().get(profile_url)).json()
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

        redirect_to = cookies_from_scope(scope).get("asgi_auth_redirect") or "/"

        headers = [["location", redirect_to]]
        login_cookie = SimpleCookie()
        login_cookie[self.cookie_name] = signed_cookie
        login_cookie[self.cookie_name]["path"] = "/"
        headers.append(["set-cookie", login_cookie.output(header="").lstrip()])
        asgi_logout_cookie = SimpleCookie()
        asgi_logout_cookie[self.logout_cookie_name] = ""
        asgi_logout_cookie[self.logout_cookie_name]["path"] = "/"
        asgi_logout_cookie[self.logout_cookie_name]["max-age"] = 0
        asgi_logout_cookie[self.logout_cookie_name]["expires"] = 0
        headers.append(["set-cookie", asgi_logout_cookie.output(header="").lstrip()])
        await send_html(send, "", 302, headers)

    async def require_auth(self, scope, receive, send):
        cookie_headers = []
        if scope["path"] in self.redirect_path_blacklist:
            return await send_html(
                send, """{}<h1>Access forbidden</h1>""".format(LOGIN_CSS), status=403
            )
        # Set asgi_auth_redirect cookie
        redirect_cookie = SimpleCookie()
        redirect_cookie[self.redirect_cookie_name] = scope["path"]
        redirect_cookie[self.redirect_cookie_name]["path"] = "/"
        cookie_headers = [["set-cookie", redirect_cookie.output(header="").lstrip()]]
        github_login_url = "https://github.com/login/oauth/authorize?scope={}&client_id={}".format(
            self.oauth_scope(), self.client_id
        )
        if self.disable_auto_login or cookies_from_scope(scope).get(
            self.logout_cookie_name
        ):
            await send_html(
                send,
                """{}<h1>Logged out</h1><p><a href="{}">Log in with GitHub</a></p>""".format(
                    LOGIN_CSS, github_login_url
                ),
                headers=cookie_headers,
            )
        else:
            await send_html(
                send, "", 302, [["location", github_login_url]] + cookie_headers
            )

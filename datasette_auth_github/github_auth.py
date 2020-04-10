import fnmatch
import hashlib
import json
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qsl, urlencode

from .utils import (
    BadSignature,
    Signer,
    force_list,
    send_html,
    cookies_from_scope,
    http_request,
)

LOGIN_CSS = """
<style>
body {
    font-family: "Helvetica Neue", sans-serif;
    font-size: 1rem;
}</style>
"""

LOGIN_BUTTON = """
<a href="{}" target="_top" style="
  text-decoration: none;
  font-family: helvetica;
  font-weight: bold;
  color: #ddd;
  background-color: black;
  height: 30px;
  display: inline-block;
  padding: 1px 12px 0 0;
  border-radius: 5px;
">
<svg xmlns="http://www.w3.org/2000/svg"
aria-label="GitHub" role="img"
viewBox="0 0 512 512" style="
  width: 30px; vertical-align: middle; border-right:0.5px solid #aaa;"
><rect
width="512" height="512" rx="15%" fill="#1B1817"/>
<path fill="#fff" d="M335 499c14 0 12 17 12 17H165s-2-17 12-17c13 0 16-6 16-12l-1-50c-71 16-86-28-86-28-12-30-28-37-28-37-24-16 1-16 1-16 26 2 40 26 40 26 22 39 59 28 74 22 2-17 9-28 16-35-57-6-116-28-116-126 0-28 10-51 26-69-3-6-11-32 3-67 0 0 21-7 70 26 42-12 86-12 128 0 49-33 70-26 70-26 14 35 6 61 3 67 16 18 26 41 26 69 0 98-60 120-117 126 10 8 18 24 18 48l-1 70c0 6 3 12 16 12z"/>
</svg>
<span style="padding-left: 5px;">Log in with GitHub</span>
</a>
"""


class GitHubAuth:
    cookie_name = "asgi_auth"
    logout_cookie_name = "asgi_auth_logout"
    redirect_cookie_name = "asgi_auth_redirect"
    callback_path = "/-/auth-callback"
    logout_path = "/-/logout"
    redirect_path_blacklist = ["/favicon.ico", "/-/static/*", "/-/static-plugins/*"]

    def __init__(
        self,
        app,
        client_id,
        client_secret,
        require_auth=False,
        cookie_ttl=60 * 60,
        cookie_version=None,
        disable_auto_login=False,
        allow_users=None,
        allow_orgs=None,
        allow_teams=None,
        cacheable_prefixes=None,
    ):
        self.app = app
        self.client_id = client_id
        self.client_secret = client_secret
        self.require_auth = require_auth
        self.cookie_ttl = cookie_ttl
        self.disable_auto_login = disable_auto_login
        self.allow_users = allow_users
        self.allow_orgs = allow_orgs
        self.allow_teams = allow_teams
        self.cacheable_prefixes = cacheable_prefixes or []
        self.team_to_team_id = {}

        cookie_version = cookie_version or "default"
        # Derive cookie_secret (used for signing cookies)
        self.cookie_secret = hashlib.pbkdf2_hmac(
            "sha256",
            "{}:{}:{}".format(client_id, client_secret, cookie_version).encode("utf8"),
            b"cookie_secret_salt",
            100000,
        )

    async def http_request(self, url, body=None, headers=None):
        return await http_request(url, body, headers)

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
        send = self.wrapped_send(send, scope)

        if scope.get("path") == self.logout_path:
            return await self.logout(scope, receive, send)

        if scope.get("path") == self.callback_path:
            return await self.auth_callback(scope, receive, send)

        auth = self.auth_from_scope(scope)
        if auth or (not self.require_auth):
            await self.app(dict(scope, auth=auth), receive, send)
        else:
            await self.handle_require_auth(scope, receive, send)

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

    def wrapped_send(self, send, scope):
        async def wrapped_send(event):
            # We only wrap http.response.start with headers
            if not (event["type"] == "http.response.start" and event.get("headers")):
                await send(event)
                return
            # Rebuild headers to include cache-control: private
            path = scope.get("path")
            original_headers = event.get("headers") or []
            if any(path.startswith(prefix) for prefix in self.cacheable_prefixes):
                await send(event)
            else:
                new_headers = [
                    [key, value]
                    for key, value in original_headers
                    if key.lower() != b"cache-control"
                ]
                new_headers.append([b"cache-control", b"private"])
                await send({**event, **{"headers": new_headers}})

        return wrapped_send

    def auth_from_scope(self, scope):
        if "auth" in scope:
            return scope["auth"]
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
                url = "https://api.github.com/orgs/{}/memberships/{}".format(
                    org, auth["username"]
                )
                response = await self.http_request(
                    url, headers={"Authorization": "token {}".format(access_token)}
                )
                if response.status_code == 200 and response.json()["state"] == "active":
                    return True
        if self.allow_teams is not None:
            for team in force_list(self.allow_teams):
                if team not in self.team_to_team_id:
                    # Look up the team_id using the GitHub API
                    org_slug, _, team_slug = team.partition("/")
                    lookup_url = "https://api.github.com/orgs/{}/teams/{}".format(
                        org_slug, team_slug
                    )
                    response = await self.http_request(
                        lookup_url,
                        headers={"Authorization": "token {}".format(access_token)},
                    )
                    if response.status_code == 200:
                        self.team_to_team_id[team] = response.json()["id"]
                    else:
                        return False
                team_id = self.team_to_team_id[team]
                # Check if the user is a member of this team
                team_membership_url = "https://api.github.com/teams/{}/memberships/{}".format(
                    team_id, auth["username"]
                )
                response = await self.http_request(
                    team_membership_url,
                    headers={"Authorization": "token {}".format(access_token)},
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
            await self.http_request(
                "https://github.com/login/oauth/access_token",
                body=urlencode(
                    {
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "code": qs["code"],
                    }
                ).encode("utf-8"),
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
        profile_url = "https://api.github.com/user"
        try:
            profile = (
                await self.http_request(
                    profile_url,
                    headers={"Authorization": "token {}".format(access_token)},
                )
            ).json()
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

        redirect_to = cookies_from_scope(scope).get(self.redirect_cookie_name) or "/"

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

    def make_redirect_cookie(self, scope):
        """cookie to tell browser where to redirect post authentication"""
        redirect_cookie = SimpleCookie()
        redirect_cookie[self.redirect_cookie_name] = scope["path"]
        redirect_cookie[self.redirect_cookie_name]["path"] = "/"
        return redirect_cookie

    def do_not_redirect(self, scope):
        return any(
            fnmatch.fnmatchcase(scope["path"], pat)
            for pat in self.redirect_path_blacklist
        )

    async def handle_require_auth(self, scope, receive, send):
        cookie_headers = []
        if self.do_not_redirect(scope):
            return await send_html(
                send, """{}<h1>Access forbidden</h1>""".format(LOGIN_CSS), status=403
            )
        # Set asgi_auth_redirect cookie
        redirect_cookie = self.make_redirect_cookie(scope)
        cookie_headers = [["set-cookie", redirect_cookie.output(header="").lstrip()]]
        github_login_url = "https://github.com/login/oauth/authorize?scope={}&client_id={}".format(
            self.oauth_scope(), self.client_id
        )
        if self.disable_auto_login or cookies_from_scope(scope).get(
            self.logout_cookie_name
        ):
            await send_html(
                send,
                """{}<h1>Logged out</h1><p>{}</p>""".format(
                    LOGIN_CSS, LOGIN_BUTTON.format(github_login_url)
                ),
                headers=cookie_headers,
            )
        else:
            await send_html(
                send, "", 302, [["location", github_login_url]] + cookie_headers
            )

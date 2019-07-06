import base64
import hashlib
import hmac
import json
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

    def __init__(self, app, cookie_secret):
        self.app = app
        self.cookie_secret = cookie_secret

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
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
        return json.loads(cookie_value)

    async def require_auth(self, scope, receive, send):
        await send_html(send, "<h1>Authentication required</h1>")


class GitHubAuth(AsgiAuth):
    callback_path = "/-/auth-callback"
    # Tests can over-ride api_client here:
    github_api_client = http3.AsyncClient()

    def __init__(
        self, app, cookie_secret, client_id, client_secret, disable_auto_login=False
    ):
        self.app = app
        self.cookie_secret = cookie_secret
        self.client_id = client_id
        self.client_secret = client_secret
        self.disable_auto_login = disable_auto_login

    async def require_auth(self, scope, receive, send):
        if scope.get("path") == self.callback_path:
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
                        LOGIN_CSS,
                        parsed["error"],
                        parsed.get("error_description") or "",
                    ),
                )
                return
            access_token = parsed.get("access_token")
            if not access_token:
                await send_html(send, "No valid access token")
                return
            # Use access_token to verify user
            profile_url = "https://api.github.com/user?access_token={}".format(
                access_token
            )
            try:
                profile = (await self.github_api_client.get(profile_url)).json()
            except ValueError:
                await send_html(send, "Could not load GitHub profile")
                return
            # Set a signed cookie and redirect to homepage
            auth = {
                "id": str(profile["id"]),
                "name": profile["name"],
                "username": profile["login"],
                "email": profile["email"],
            }
            signer = Signer(self.cookie_secret)
            signed_cookie = signer.sign(json.dumps(auth))
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
        else:
            github_login_url = "https://github.com/login/oauth/authorize?scope=user:email&client_id={}".format(
                self.client_id
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


@hookimpl
def asgi_wrapper(datasette):
    config = datasette.plugin_config("datasette-auth-github") or {}
    client_id = config.get("client_id")
    client_secret = config.get("client_secret")
    disable_auto_login = bool(config.get("disable_auto_login"))

    def wrap_with_asgi_auth(app):
        if not (client_id and client_secret):
            return app

        cookie_secret = salted_hmac("cookie_secret", client_id, client_secret).digest()
        return GitHubAuth(
            app,
            cookie_secret=cookie_secret,
            client_id=client_id,
            client_secret=client_secret,
            disable_auto_login=disable_auto_login,
        )

    return wrap_with_asgi_auth


@hookimpl
def extra_template_vars(request):
    return {"auth": request.scope.get("auth")}

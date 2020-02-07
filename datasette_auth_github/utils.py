import asyncio
import base64
import hashlib
import hmac
from http.cookies import SimpleCookie
import json
import urllib.request

SALT = "datasette-auth-github"


class BadSignature(Exception):
    pass


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
        headers.append(["content-type", "text/html; charset=UTF-8"])
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


async def http_request(url, body=None, headers=None):
    "Performs POST if body provided, GET otherwise."
    headers = headers or {}

    def _request():
        message = urllib.request.urlopen(urllib.request.Request(url, body, headers))
        return message.status, tuple(message.headers.raw_items()), message.read()

    loop = asyncio.get_event_loop()
    status_code, headers, body = await loop.run_in_executor(None, _request)
    return Response(status_code, headers, body)


class Response:
    "Wrapper class making HTTP responses easier to work with"

    def __init__(self, status_code, headers, body):
        self.status_code = status_code
        self.headers = headers
        self.body = body

    def json(self):
        return json.loads(self.text)

    @property
    def text(self):
        # Should decode according to Content-Type, for the moment assumes utf8
        return self.body.decode("utf-8")


def ensure_bytes(s):
    if not isinstance(s, bytes):
        return s.encode("utf-8")
    else:
        return s


def force_list(value):
    if isinstance(value, str):
        return [value]
    return value


def salted_hmac(salt, value, secret):
    salt = ensure_bytes(salt)
    secret = ensure_bytes(secret)
    key = hashlib.sha1(salt + secret).digest()
    return hmac.new(key, msg=ensure_bytes(value), digestmod=hashlib.sha1)


def cookies_from_scope(scope):
    cookie = dict(scope.get("headers") or {}).get(b"cookie")
    if not cookie:
        return {}
    simple_cookie = SimpleCookie()
    simple_cookie.load(cookie.decode("utf8"))
    return {key: morsel.value for key, morsel in simple_cookie.items()}

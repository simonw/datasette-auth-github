import json
import time
from http.cookies import SimpleCookie

import pytest
from asgiref.testing import ApplicationCommunicator
from http3 import AsyncClient, AsyncDispatcher, AsyncResponse, codes

from datasette_auth_github import GitHubAuth
from datasette_auth_github.utils import Signer


@pytest.fixture
def wrapped_app():
    return GitHubAuth(
        hello_world_app, client_id="x_client_id", client_secret="x_client_secret"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/", "/fixtures", "/foo/bar"])
async def test_redirects_to_github_with_asgi_auth_redirect_cookie(path, wrapped_app):
    instance = ApplicationCommunicator(
        wrapped_app,
        {"type": "http", "http_version": "1.0", "method": "GET", "path": path},
    )
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    assert "http.response.start" == output["type"]
    assert 302 == output["status"]
    headers = tuple([tuple(pair) for pair in output["headers"]])
    assert (
        b"location",
        b"https://github.com/login/oauth/authorize?scope=user:email&client_id=x_client_id",
    ) in headers
    assert (b"cache-control", b"private") in headers
    simple_cookie = SimpleCookie()
    for key, value in headers:
        if key == b"set-cookie":
            simple_cookie.load(value.decode("utf8"))
    assert path == simple_cookie["asgi_auth_redirect"].value
    assert (await instance.receive_output(1)) == {
        "type": "http.response.body",
        "body": b"",
    }


@pytest.mark.asyncio
async def test_logged_out_favicon_forbidden(wrapped_app):
    instance = ApplicationCommunicator(
        wrapped_app,
        {
            "type": "http",
            "http_version": "1.0",
            "method": "GET",
            "path": "/favicon.ico",
        },
    )
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    assert "http.response.start" == output["type"]
    assert 403 == output["status"]


@pytest.mark.asyncio
@pytest.mark.parametrize("redirect_path", ["/", "/fixtures", "/foo/bar"])
async def test_auth_callback_calls_github_apis_and_sets_cookie(
    redirect_path, wrapped_app
):
    wrapped_app.github_api_client_factory = lambda: AsyncClient(
        dispatch=MockGithubApiDispatch()
    )
    cookie = SimpleCookie()
    cookie["asgi_auth_redirect"] = redirect_path
    cookie["asgi_auth_redirect"]["path"] = "/"
    instance = ApplicationCommunicator(
        wrapped_app,
        {
            "type": "http",
            "http_version": "1.0",
            "method": "GET",
            "path": "/-/auth-callback",
            "query_string": b"code=github-code-here",
            "headers": [[b"cookie", cookie.output(header="").lstrip().encode("utf8")]],
        },
    )
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    assert_redirects_and_sets_cookie(wrapped_app, output, redirect_path)


def assert_redirects_and_sets_cookie(app, output, redirect_to="/"):
    assert "http.response.start" == output["type"]
    assert 302 == output["status"]
    # Convert headers into a tuple of tuples for x in y lookups
    headers = tuple([tuple(pair) for pair in output["headers"]])
    assert (b"location", redirect_to.encode("utf8")) in headers
    assert (b"content-type", b"text/html; charset=UTF-8") in headers
    assert (b"cache-control", b"private") in headers
    # ... and confirm the cookie was set
    cookie_values = [value for key, value in headers if key == b"set-cookie"]
    signer = Signer(app.cookie_secret)
    simple_cookie = SimpleCookie()
    for cookie_value in cookie_values:
        simple_cookie.load(cookie_value.decode("utf8"))
    cookie_dict = {key: morsel.value for key, morsel in simple_cookie.items()}
    decoded = json.loads(signer.unsign(cookie_dict["asgi_auth"]))
    assert "123" == decoded["id"]
    assert "demouser" == decoded["username"]
    assert isinstance(decoded["ts"], int)
    # Should also clear asgi_auth_logout cookie
    assert "" == cookie_dict["asgi_auth_logout"]
    assert "0" == simple_cookie["asgi_auth_logout"]["max-age"]


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/", "/favicon.ico", "/fixtures"])
async def test_signed_cookie_allows_access(path, wrapped_app):
    scope = {
        "type": "http",
        "http_version": "1.0",
        "method": "GET",
        "path": path,
        "headers": [
            [b"cookie", signed_auth_cookie_header(wrapped_app)],
            [b"cache-control", b"private"],
        ],
    }
    instance = ApplicationCommunicator(wrapped_app, scope)
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    assert {
        "type": "http.response.start",
        "status": 200,
        "headers": [
            [b"content-type", b"text/html; charset=UTF-8"],
            [b"cache-control", b"private"],
        ],
    } == output


@pytest.mark.asyncio
async def test_corrupt_cookie_signature_is_denied_access(wrapped_app):
    cookie = signed_auth_cookie_header(wrapped_app)
    # Corrupt the signature
    body, sig = cookie.rsplit(b":", 1)
    corrupt_cookie = body + b":" + b"x" + sig
    instance = ApplicationCommunicator(
        wrapped_app,
        {
            "type": "http",
            "http_version": "1.0",
            "method": "GET",
            "path": "/",
            "headers": [[b"cookie", corrupt_cookie]],
        },
    )
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    assert 302 == output["status"]


@pytest.mark.asyncio
async def test_expired_cookie_is_denied_access(wrapped_app):
    cookie = signed_auth_cookie_header(wrapped_app, ts=time.time() - 36 * 60 * 60)
    # Corrupt the signature
    instance = ApplicationCommunicator(
        wrapped_app,
        {
            "type": "http",
            "http_version": "1.0",
            "method": "GET",
            "path": "/",
            "headers": [[b"cookie", cookie]],
        },
    )
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    assert 302 == output["status"]


@pytest.mark.asyncio
async def test_incrementing_cookie_version_denies_access():
    app = GitHubAuth(
        hello_world_app, client_id="x_client_id", client_secret="x_client_secret"
    )
    cookie = signed_auth_cookie_header(app)
    scope = {
        "type": "http",
        "http_version": "1.0",
        "method": "GET",
        "path": "/",
        "headers": [[b"cookie", cookie]],
    }
    instance = ApplicationCommunicator(app, scope)
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    assert 200 == output["status"]
    # Try it again with a different cookie version
    app = GitHubAuth(
        hello_world_app,
        client_id="x_client_id",
        client_secret="x_client_secret",
        cookie_version=2,
    )
    instance = ApplicationCommunicator(app, scope)
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    assert 302 == output["status"]


@pytest.mark.asyncio
async def test_invalid_github_code_denied_access(wrapped_app):
    wrapped_app.github_api_client_factory = lambda: AsyncClient(
        dispatch=MockGithubApiDispatch(
            b"error=bad_verification_code&error_description=The+code+passed+is+incorrect"
        )
    )
    instance = ApplicationCommunicator(
        wrapped_app,
        {
            "type": "http",
            "http_version": "1.0",
            "method": "GET",
            "path": "/-/auth-callback",
            "query_string": b"code=github-code-here",
        },
    )
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    # Should show error
    assert 200 == output["status"]
    output = await instance.receive_output(1)
    assert b"<h1>GitHub authentication error</h1>" in output["body"]


@pytest.mark.asyncio
async def test_logout(wrapped_app):
    instance = ApplicationCommunicator(
        wrapped_app,
        {"type": "http", "http_version": "1.0", "method": "GET", "path": "/-/logout"},
    )
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    assert {"type": "http.response.start", "status": 302} == {
        "type": output["type"],
        "status": output["status"],
    }
    headers = tuple([tuple(pair) for pair in output["headers"]])
    assert (b"location", b"/") in headers
    assert (b"set-cookie", b"asgi_auth_logout=stay-logged-out; Path=/") in headers
    assert (b"content-type", b"text/html; charset=UTF-8") in headers
    assert (b"cache-control", b"private") in headers
    # asgi_auth should have been set with max-age and expiry
    asgi_auth_cookie = [
        p[1]
        for p in headers
        if p[0] == b"set-cookie" and p[1].startswith(b"asgi_auth=")
    ][0]
    assert b"Max-Age=0" in asgi_auth_cookie
    assert b"Path=/" in asgi_auth_cookie
    assert b"expires=" in asgi_auth_cookie


async def assert_returns_logged_out_screen(instance, path):
    output = await instance.receive_output(1)
    assert 200 == output["status"]
    assert "http.response.start" == output["type"]
    headers = tuple([tuple(pair) for pair in output["headers"]])
    assert (b"content-type", b"text/html; charset=UTF-8") in headers
    assert (b"cache-control", b"private") in headers
    simple_cookie = SimpleCookie()
    for key, value in headers:
        if key == b"set-cookie":
            simple_cookie.load(value.decode("utf8"))
    assert path == simple_cookie["asgi_auth_redirect"].value
    output = await instance.receive_output(1)
    assert b"<h1>Logged out</h1>" in output["body"]
    assert b"https://github.com/login/oauth/authorize?scope" in output["body"]


@pytest.mark.asyncio
async def test_disable_auto_login_respected(wrapped_app):
    wrapped_app.disable_auto_login = True
    instance = ApplicationCommunicator(
        wrapped_app,
        {"type": "http", "http_version": "1.0", "method": "GET", "path": "/"},
    )
    await instance.send_input({"type": "http.request"})
    await assert_returns_logged_out_screen(instance, "/")


@pytest.mark.asyncio
async def test_stay_logged_out_is_respected(wrapped_app):
    instance = ApplicationCommunicator(
        wrapped_app,
        {
            "type": "http",
            "http_version": "1.0",
            "method": "GET",
            "path": "/",
            "headers": [[b"cookie", b"asgi_auth_logout=stay-logged-out"]],
        },
    )
    await instance.send_input({"type": "http.request"})
    await assert_returns_logged_out_screen(instance, ("/"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "attr,attr_value,should_allow",
    [
        ["allow_users", ["otheruser"], False],
        ["allow_users", ["demouser"], True],
        ["allow_users", "otheruser", False],
        ["allow_users", "demouser", True],
        ["allow_orgs", ["my-org"], False],
        ["allow_orgs", ["demouser-org"], True],
        ["allow_orgs", ["pending-org"], False],
        ["allow_orgs", "my-org", False],
        ["allow_orgs", "demouser-org", True],
        ["allow_orgs", "pending-org", False],
        ["allow_teams", ["my-org/hello"], False],
        ["allow_teams", ["demouser-org/thetopteam"], True],
        ["allow_teams", ["demouser-org/pendingteam"], False],
        ["allow_teams", "my-org/hello", False],
        ["allow_teams", "demouser-org/thetopteam", True],
        ["allow_teams", "demouser-org/pendingteam", False],
    ],
)
async def test_allow_rules(attr, attr_value, should_allow, wrapped_app):
    setattr(wrapped_app, attr, attr_value)
    wrapped_app.github_api_client_factory = lambda: AsyncClient(
        dispatch=MockGithubApiDispatch()
    )
    scope = {
        "type": "http",
        "http_version": "1.0",
        "method": "GET",
        "path": "/-/auth-callback",
        "query_string": b"code=github-code-here",
    }
    instance = ApplicationCommunicator(wrapped_app, scope)
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    if should_allow:
        # Should redirect to homepage
        assert_redirects_and_sets_cookie(wrapped_app, output)
    else:
        # Should return forbidden
        assert {"type": "http.response.start", "status": 403} == {
            "type": output["type"],
            "status": output["status"],
        }


@pytest.mark.asyncio
async def test_allow_orgs(wrapped_app):
    wrapped_app.allow_orgs = ["my-org"]
    wrapped_app.github_api_client_factory = lambda: AsyncClient(
        dispatch=MockGithubApiDispatch()
    )
    scope = {
        "type": "http",
        "http_version": "1.0",
        "method": "GET",
        "path": "/-/auth-callback",
        "query_string": b"code=github-code-here",
    }
    instance = ApplicationCommunicator(wrapped_app, scope)
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    # Should return forbidden
    assert {"type": "http.response.start", "status": 403} == {
        "type": output["type"],
        "status": output["status"],
    }
    # Try again with an org they are a member of
    wrapped_app.allow_orgs = ["demouser-org"]
    instance = ApplicationCommunicator(wrapped_app, scope)
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    assert 302 == output["status"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "config,expected_scope",
    [
        [{"allow_orgs": ["foo"]}, "user"],
        [{"allow_users": ["foo"]}, "user:email"],
        [{"allow_teams": ["foo/blah"]}, "read:org"],
    ],
)
async def test_oauth_scope(config, expected_scope, wrapped_app):
    for key, value in config.items():
        setattr(wrapped_app, key, value)
    instance = ApplicationCommunicator(
        wrapped_app,
        {"type": "http", "http_version": "1.0", "method": "GET", "path": "/"},
    )
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    expected_location = "https://github.com/login/oauth/authorize?scope={}&client_id=x_client_id".format(
        expected_scope
    ).encode(
        "utf8"
    )
    location = dict(output["headers"]).get(b"location")
    assert expected_location == location


def signed_auth_cookie_header(app, ts=None):
    signer = Signer(app.cookie_secret)
    cookie = SimpleCookie()
    cookie["asgi_auth"] = signer.sign(
        json.dumps(
            {
                "id": "123",
                "name": "GitHub User",
                "username": "demouser",
                "email": "demouser@example.com",
                "ts": ts or int(time.time()),
            },
            separators=(",", ":"),
        )
    )
    cookie["asgi_auth"]["path"] = "/"
    return cookie.output(header="").lstrip().encode("utf8")


async def hello_world_app(scope, receive, send):
    assert scope["type"] == "http"
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                [b"content-type", b"text/html; charset=UTF-8"],
                [b"cache-control", b"max-age=123"],
            ],
        }
    )
    await send({"type": "http.response.body", "body": b'{"hello": "world"}'})


class MockGithubApiDispatch(AsyncDispatcher):
    def __init__(self, access_token_response=b"access_token=x_access_token"):
        self.access_token_response = access_token_response

    async def send(self, request, verify=None, cert=None, timeout=None):
        if request.url.path == "/login/oauth/access_token" and request.method == "POST":
            return AsyncResponse(
                codes.OK, content=self.access_token_response, request=request
            )
        elif (
            request.url.path.startswith("/orgs/")
            and "/memberships/" in request.url.path
        ):
            # It's an organization membership check
            org = request.url.path.split("/orgs/")[1].split("/")[0]
            if org in ("demouser-org", "pending-org"):
                member_state = {"demouser-org": "active", "pending-org": "pending"}[org]
                return AsyncResponse(
                    codes.OK,
                    content=json.dumps(
                        {"state": member_state, "role": "member"}
                    ).encode("utf8"),
                    request=request,
                )
            else:
                return AsyncResponse(
                    codes.FORBIDDEN,
                    content=json.dumps({"message": "Not a member"}).encode("utf8"),
                    request=request,
                )
        elif request.url.path.startswith("/orgs/") and "/teams/" in request.url.path:
            # /orgs/eventbrite/teams/engineering team ID lookup
            team_slug = request.url.path.split("/")[-1]
            if team_slug in ("thetopteam", "pendingteam"):
                team_info = {
                    "thetopteam": {
                        "id": 54321,
                        "name": "The Top Team",
                        "slug": "thetopteam",
                    },
                    "pendingteam": {
                        "id": 59999,
                        "name": "Pending Team",
                        "slug": "pendingteam",
                    },
                }[team_slug]
                return AsyncResponse(
                    codes.OK,
                    content=json.dumps(team_info).encode("utf-8"),
                    request=request,
                )
            else:
                return AsyncResponse(
                    codes.NOT_FOUND,
                    content=json.dumps({"message": "Not found"}).encode("utf8"),
                    request=request,
                )
        elif (
            request.url.path.startswith("/teams/")
            and "/memberships/" in request.url.path
        ):
            # Team membership check
            if "54321" in request.url.path:
                return AsyncResponse(
                    codes.OK,
                    content=json.dumps({"state": "active", "role": "member"}).encode(
                        "utf8"
                    ),
                    request=request,
                )
            elif "59999" in request.url.path:
                # User is pending in this team
                return AsyncResponse(
                    codes.OK,
                    content=json.dumps({"state": "pending", "role": "member"}).encode(
                        "utf8"
                    ),
                    request=request,
                )
            else:
                return AsyncResponse(
                    codes.NOT_FOUND,
                    content=json.dumps({"message": "Not found"}).encode("utf8"),
                    request=request,
                )
        elif (
            request.url.path == "/user"
            and request.url.query == "access_token=x_access_token"
            and request.method == "GET"
        ):
            return AsyncResponse(
                codes.OK,
                content=json.dumps(
                    {
                        "id": 123,
                        "name": "GitHub User",
                        "login": "demouser",
                        "email": "demouser@example.com",
                    }
                ).encode("utf-8"),
                request=request,
            )

import json
import pathlib
import re
import time
from http.cookies import SimpleCookie

import pytest
from asgiref.testing import ApplicationCommunicator

from datasette.app import Datasette

from datasette_auth_github import GitHubAuth as GitHubAuthOriginal
from datasette_auth_github.utils import Signer, Response


@pytest.fixture
def require_auth_app():
    return GitHubAuth(
        hello_world_app,
        client_id="x_client_id",
        client_secret="x_client_secret",
        require_auth=True,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/", "/fixtures", "/foo/bar"])
async def test_redirects_to_github_with_asgi_auth_redirect_cookie(
    path, require_auth_app
):
    instance = ApplicationCommunicator(
        require_auth_app,
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
async def test_logged_out_favicon_forbidden(require_auth_app):
    instance = ApplicationCommunicator(
        require_auth_app,
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
    redirect_path, require_auth_app
):
    cookie = SimpleCookie()
    cookie["asgi_auth_redirect"] = redirect_path
    cookie["asgi_auth_redirect"]["path"] = "/"
    instance = ApplicationCommunicator(
        require_auth_app,
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
    assert_redirects_and_sets_cookie(require_auth_app, output, redirect_path)


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
async def test_signed_cookie_allows_access(path, require_auth_app):
    scope = {
        "type": "http",
        "http_version": "1.0",
        "method": "GET",
        "path": path,
        "headers": [
            [b"cookie", signed_auth_cookie_header(require_auth_app)],
            [b"cache-control", b"private"],
        ],
    }
    instance = ApplicationCommunicator(require_auth_app, scope)
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
    # Should have got back the auth information we passed in
    output = await instance.receive_output(1)
    body_data = json.loads(output["body"].decode("utf8"))
    assert "world" == body_data["hello"]
    auth = body_data["auth"]
    assert "123" == auth["id"]
    assert "GitHub User" == auth["name"]
    assert "demouser" == auth["username"]
    assert "demouser@example.com" == auth["email"]
    assert isinstance(auth["ts"], int)


@pytest.mark.asyncio
async def test_corrupt_cookie_signature_is_denied_access(require_auth_app):
    cookie = signed_auth_cookie_header(require_auth_app)
    # Corrupt the signature
    body, sig = cookie.rsplit(b":", 1)
    corrupt_cookie = body + b":" + b"x" + sig
    instance = ApplicationCommunicator(
        require_auth_app,
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
@pytest.mark.parametrize(
    "cookie_age,should_allow", [((3600 - 10), True), ((3600 + 10), False)]
)
async def test_expired_cookie_is_denied_access(
    cookie_age, should_allow, require_auth_app
):
    cookie = signed_auth_cookie_header(require_auth_app, ts=time.time() - cookie_age)
    instance = ApplicationCommunicator(
        require_auth_app,
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
    if should_allow:
        assert 200 == output["status"]
    else:
        assert 302 == output["status"]


@pytest.mark.asyncio
async def test_incrementing_cookie_version_denies_access():
    app = GitHubAuth(
        hello_world_app,
        client_id="x_client_id",
        client_secret="x_client_secret",
        require_auth=True,
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
        require_auth=True,
        cookie_version=2,
    )
    instance = ApplicationCommunicator(app, scope)
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    assert 302 == output["status"]


@pytest.mark.asyncio
async def test_invalid_github_code_denied_access(require_auth_app):
    require_auth_app.access_token_response = (
        b"error=bad_verification_code&error_description=The+code+passed+is+incorrect"
    )
    instance = ApplicationCommunicator(
        require_auth_app,
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
async def test_logout(require_auth_app):
    instance = ApplicationCommunicator(
        require_auth_app,
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
async def test_disable_auto_login_respected(require_auth_app):
    require_auth_app.disable_auto_login = True
    instance = ApplicationCommunicator(
        require_auth_app,
        {"type": "http", "http_version": "1.0", "method": "GET", "path": "/"},
    )
    await instance.send_input({"type": "http.request"})
    await assert_returns_logged_out_screen(instance, "/")


@pytest.mark.asyncio
async def test_stay_logged_out_is_respected(require_auth_app):
    instance = ApplicationCommunicator(
        require_auth_app,
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
async def test_allow_rules(attr, attr_value, should_allow, require_auth_app):
    setattr(require_auth_app, attr, attr_value)
    scope = {
        "type": "http",
        "http_version": "1.0",
        "method": "GET",
        "path": "/-/auth-callback",
        "query_string": b"code=github-code-here",
    }
    instance = ApplicationCommunicator(require_auth_app, scope)
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    if should_allow:
        # Should redirect to homepage
        assert_redirects_and_sets_cookie(require_auth_app, output)
    else:
        # Should return forbidden
        assert {"type": "http.response.start", "status": 403} == {
            "type": output["type"],
            "status": output["status"],
        }


@pytest.mark.asyncio
async def test_allow_orgs(require_auth_app):
    require_auth_app.allow_orgs = ["my-org"]
    scope = {
        "type": "http",
        "http_version": "1.0",
        "method": "GET",
        "path": "/-/auth-callback",
        "query_string": b"code=github-code-here",
    }
    instance = ApplicationCommunicator(require_auth_app, scope)
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    # Should return forbidden
    assert {"type": "http.response.start", "status": 403} == {
        "type": output["type"],
        "status": output["status"],
    }
    # Try again with an org they are a member of
    require_auth_app.allow_orgs = ["demouser-org"]
    instance = ApplicationCommunicator(require_auth_app, scope)
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
async def test_oauth_scope(config, expected_scope, require_auth_app):
    for key, value in config.items():
        setattr(require_auth_app, key, value)
    instance = ApplicationCommunicator(
        require_auth_app,
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


@pytest.mark.asyncio
async def test_require_auth_false(require_auth_app):
    scope = {"type": "http", "http_version": "1.0", "method": "GET", "path": "/"}
    # Should redirect if require_auth=True:
    instance = ApplicationCommunicator(require_auth_app, scope)
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    assert 302 == output["status"]
    # Should 200 if require_auth=False
    require_auth_app.require_auth = False
    instance = ApplicationCommunicator(require_auth_app, scope)
    await instance.send_input({"type": "http.request"})
    output2 = await instance.receive_output(1)
    assert 200 == output2["status"]
    # And scope["auth"] should have been None
    body = await instance.receive_output(1)
    assert {"hello": "world", "auth": None} == json.loads(body["body"].decode("utf8"))


@pytest.mark.asyncio
async def test_cacheable_assets(require_auth_app):
    # Anything with a path matching cacheable_prefixes should not
    # have a cache-control: private header
    require_auth_app.cacheable_prefixes = ["/-/static/"]
    scope = {
        "type": "http",
        "http_version": "1.0",
        "method": "GET",
        "path": "/-/static/blah.js",
        "headers": [[b"cookie", signed_auth_cookie_header(require_auth_app)]],
    }
    instance = ApplicationCommunicator(require_auth_app, scope)
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    assert [
        [b"content-type", b"text/html; charset=UTF-8"],
        [b"cache-control", b"max-age=123"],
    ] == output["headers"]
    # BUT... if we reset cacheable_prefixes to [] it should behave as default:
    require_auth_app.cacheable_prefixes = []
    instance = ApplicationCommunicator(require_auth_app, scope)
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    assert [
        [b"content-type", b"text/html; charset=UTF-8"],
        [b"cache-control", b"private"],
    ] == output["headers"]


@pytest.mark.asyncio
async def test_datasette_plugin_installed():
    instance = ApplicationCommunicator(
        Datasette([], memory=True).app(),
        {
            "type": "http",
            "http_version": "1.0",
            "method": "GET",
            "path": "/-/plugins.json",
        },
    )
    await instance.send_input({"type": "http.request"})
    response_start = await instance.receive_output(1)
    assert "http.response.start" == response_start["type"]
    assert 200 == response_start["status"]
    body = await instance.receive_output(1)
    assert [
        {
            "name": "datasette_auth_github",
            "static": False,
            "templates": True,
            "version": get_version_string(),
        }
    ] == json.loads(body["body"].decode("utf8"))


@pytest.mark.asyncio
async def test_require_auth_is_true_when_used_as_datasette_plugin():
    app = Datasette(
        [],
        memory=True,
        metadata={
            "plugins": {
                "datasette-auth-github": {
                    "client_id": "client_x",
                    "client_secret": "client_secret_x",
                }
            }
        },
    ).app()
    assert isinstance(app, GitHubAuthOriginal)
    assert True == app.require_auth


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
    await send(
        {
            "type": "http.response.body",
            "body": json.dumps({"hello": "world", "auth": scope.get("auth")}).encode(
                "utf8"
            ),
        }
    )


def get_version_string():
    # Extract 'VERSION = "0.6.3"' from setup.py
    contents = (pathlib.Path(__file__).parent / "setup.py").read_text()
    m = re.search(r'VERSION = "(.*?)"', contents)
    return m.group(1)


class GitHubAuth(GitHubAuthOriginal):
    access_token_response = b"access_token=x_access_token"

    async def http_request(self, url, body=None):
        method = "GET" if body is None else "POST"
        path = url.split("github.com")[1]
        if path == "/login/oauth/access_token" and method == "POST":
            return Response(200, (), self.access_token_response)
        elif path.startswith("/orgs/") and "/memberships/" in path:
            # It's an organization membership check
            org = path.split("/orgs/")[1].split("/")[0]
            if org in ("demouser-org", "pending-org"):
                member_state = {"demouser-org": "active", "pending-org": "pending"}[org]
                return Response(
                    200,
                    (),
                    json.dumps({"state": member_state, "role": "member"}).encode(
                        "utf8"
                    ),
                )
            else:
                return Response(
                    403, (), json.dumps({"message": "Not a member"}).encode("utf8")
                )
        elif path.startswith("/orgs/") and "/teams/" in path:
            # /orgs/eventbrite/teams/engineering team ID lookup
            team_slug = path.split("/")[-1].split("?")[0]
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
                return Response(200, (), json.dumps(team_info).encode("utf-8"))
            else:
                return Response(
                    404, (), json.dumps({"message": "Not found"}).encode("utf8")
                )
        elif path.startswith("/teams/") and "/memberships/" in path:
            # Team membership check
            if "54321" in path:
                return Response(
                    200,
                    (),
                    json.dumps({"state": "active", "role": "member"}).encode("utf8"),
                )
            elif "59999" in path:
                # User is pending in this team
                return Response(
                    200,
                    (),
                    json.dumps({"state": "pending", "role": "member"}).encode("utf8"),
                )
            else:
                return Response(
                    404, (), json.dumps({"message": "Not found"}).encode("utf8")
                )
        elif (
            path.startswith("/user")
            and "access_token=x_access_token" in path
            and method == "GET"
        ):
            return Response(
                200,
                (),
                json.dumps(
                    {
                        "id": 123,
                        "name": "GitHub User",
                        "login": "demouser",
                        "email": "demouser@example.com",
                    }
                ).encode("utf-8"),
            )

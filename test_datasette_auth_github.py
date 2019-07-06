import json

import pytest
from asgiref.testing import ApplicationCommunicator
from http3 import AsyncClient, AsyncDispatcher, AsyncResponse, codes

from datasette_auth_github import GitHubAuth

DEMO_USER_SIGNED_COOKIE = b'asgi_auth="{\\"id\\": \\"123\\"\\054 \\"name\\": \\"GitHub User\\"\\054 \\"username\\": \\"demouser\\"\\054 \\"email\\": \\"demouser@example.com\\"}:IvBRqdgUQfPCvnMwhvmm2iH-6cY"; Path=/'


@pytest.fixture
def wrapped_app():
    return GitHubAuth(
        hello_world_app,
        cookie_secret="secret",
        client_id="x_client_id",
        client_secret="x_client_secret",
    )


@pytest.mark.asyncio
async def test_wrapped_app_redirects_to_github(wrapped_app):
    instance = ApplicationCommunicator(
        wrapped_app,
        {"type": "http", "http_version": "1.0", "method": "GET", "path": "/"},
    )
    await instance.send_input({"type": "http.request"})
    assert (await instance.receive_output(1)) == {
        "type": "http.response.start",
        "status": 302,
        "headers": [
            [
                b"location",
                b"https://github.com/login/oauth/authorize?scope=user:email&client_id=x_client_id",
            ],
            [b"content-type", b"text/html"],
            [b"cache-control", b"private"],
        ],
    }
    assert (await instance.receive_output(1)) == {
        "type": "http.response.body",
        "body": b"",
    }


@pytest.mark.asyncio
async def test_oauth_callback_call_apis_and_sets_cookie(wrapped_app):
    wrapped_app.github_api_client = AsyncClient(dispatch=MockGithubApiDispatch())
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
    # Should set asgi_auth cookie
    assert {
        "type": "http.response.start",
        "status": 302,
        "headers": [
            [b"location", b"/"],
            [b"set-cookie", DEMO_USER_SIGNED_COOKIE],
            [b"content-type", b"text/html"],
            [b"cache-control", b"private"],
        ],
    } == output


@pytest.mark.asyncio
async def test_signed_cookie_allows_access(wrapped_app):
    instance = ApplicationCommunicator(
        wrapped_app,
        {
            "type": "http",
            "http_version": "1.0",
            "method": "GET",
            "path": "/",
            "headers": [
                [b"cookie", DEMO_USER_SIGNED_COOKIE],
                [b"cache-control", b"private"],
            ],
        },
    )
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    assert {
        "type": "http.response.start",
        "status": 200,
        "headers": [[b"content-type", b"text/html"], [b"cache-control", b"private"]],
    } == output


@pytest.mark.asyncio
async def test_corrupt_cookie_signature_is_denied_access(wrapped_app):
    cookie = DEMO_USER_SIGNED_COOKIE
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
async def test_invalid_github_code_denied_access(wrapped_app):
    wrapped_app.github_api_client = AsyncClient(
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
    assert {
        "type": "http.response.start",
        "status": 302,
        "headers": [
            [b"location", b"/"],
            [b"set-cookie", b'asgi_auth=""; Path=/'],
            [b"set-cookie", b"asgi_auth_logout=stay-logged-out; Path=/"],
            [b"content-type", b"text/html"],
            [b"cache-control", b"private"],
        ],
    } == output


async def assert_returns_logged_out_screen(instance):
    output = await instance.receive_output(1)
    assert {
        "type": "http.response.start",
        "status": 200,
        "headers": [[b"content-type", b"text/html"], [b"cache-control", b"private"]],
    } == output
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
    await assert_returns_logged_out_screen(instance)


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
    await assert_returns_logged_out_screen(instance)


@pytest.mark.asyncio
async def test_allow_users(wrapped_app):
    wrapped_app.allow_users = ["otheruser"]
    wrapped_app.github_api_client = AsyncClient(dispatch=MockGithubApiDispatch())
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
    # Try again with demouser whitelisted
    wrapped_app.allow_users = ["demouser"]
    instance = ApplicationCommunicator(wrapped_app, scope)
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    assert 302 == output["status"]


@pytest.mark.asyncio
async def test_allow_orgs(wrapped_app):
    wrapped_app.allow_orgs = ["my-org"]
    wrapped_app.github_api_client = AsyncClient(dispatch=MockGithubApiDispatch())
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


async def hello_world_app(scope, receive, send):
    assert scope["type"] == "http"
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                [b"content-type", b"text/html"],
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
            if org == "demouser-org":
                return AsyncResponse(
                    codes.OK,
                    content=json.dumps({"state": "active", "role": "member"}).encode(
                        "utf8"
                    ),
                    request=request,
                )
            else:
                return AsyncResponse(
                    codes.FORBIDDEN,
                    content=json.dumps({"message": "Not a member"}).encode("utf8"),
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

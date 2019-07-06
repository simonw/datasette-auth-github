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
        ],
    }
    assert (await instance.receive_output(1)) == {
        "type": "http.response.body",
        "body": b"",
    }


@pytest.mark.asyncio
async def test_oauth_callback_call_apis_and_sets_cooki(wrapped_app):
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
            "headers": [[b"cookie", DEMO_USER_SIGNED_COOKIE]],
        },
    )
    await instance.send_input({"type": "http.request"})
    output = await instance.receive_output(1)
    assert {
        "type": "http.response.start",
        "status": 200,
        "headers": [[b"content-type", b"text/html"]],
    } == output


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
        ],
    } == output


async def assert_returns_logged_out_screen(instance):
    output = await instance.receive_output(1)
    assert {
        "type": "http.response.start",
        "status": 200,
        "headers": [[b"content-type", b"text/html"]],
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


async def hello_world_app(scope, receive, send):
    assert scope["type"] == "http"
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [[b"content-type", b"text/html"]],
        }
    )
    await send({"type": "http.response.body", "body": b'{"hello": "world"}'})


class MockGithubApiDispatch(AsyncDispatcher):
    async def send(self, request, verify=None, cert=None, timeout=None):
        if request.url.path == "/login/oauth/access_token" and request.method == "POST":
            return AsyncResponse(
                codes.OK, content=b"access_token=x_access_token", request=request
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

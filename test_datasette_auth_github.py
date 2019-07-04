from asgiref.testing import ApplicationCommunicator
from datasette_auth_github import GitHubAuth

import pytest


@pytest.fixture
def wrapped_app():
    return GitHubAuth(
        hello_world_app,
        cookie_secret="secret",
        client_id="x_client_id",
        client_secret="x_client_secret",
    )


@pytest.mark.asyncio
async def test_wrapped_app_redirects(wrapped_app):
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


async def hello_world_app(scope, receive, send):
    assert scope["type"] == "http"
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [[b"content-type", b"application/json"]],
        }
    )
    await send({"type": "http.response.body", "body": b'{"hello": "world"}'})

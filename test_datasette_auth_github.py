from datasette.app import Datasette
from datasette_auth_github import utils, views
import httpx
import json
import pytest
import sqlite_utils


async def stub_http_request(url, body=None, headers=None):
    headers = headers or {}
    method = "GET" if body is None else "POST"
    path = url.split("github.com")[1]
    if path == "/login/oauth/access_token" and method == "POST":
        return utils.Response(200, (), b"access_token=x_access_token")
    elif path.startswith("/orgs/") and "/memberships/" in path:
        # It's an organization membership check
        org = path.split("/orgs/")[1].split("/")[0]
        if org in ("demouser-org", "pending-org"):
            member_state = {"demouser-org": "active", "pending-org": "pending"}[org]
            return utils.Response(
                200,
                (),
                json.dumps({"state": member_state, "role": "member"}).encode("utf8"),
            )
        else:
            return utils.Response(
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
            return utils.Response(200, (), json.dumps(team_info).encode("utf-8"))
        else:
            return utils.Response(
                404, (), json.dumps({"message": "Not found"}).encode("utf8")
            )
    elif path.startswith("/teams/") and "/memberships/" in path:
        # Team membership check
        if "54321" in path:
            return utils.Response(
                200,
                (),
                json.dumps({"state": "active", "role": "member"}).encode("utf8"),
            )
        elif "59999" in path:
            # User is pending in this team
            return utils.Response(
                200,
                (),
                json.dumps({"state": "pending", "role": "member"}).encode("utf8"),
            )
        else:
            return utils.Response(
                404, (), json.dumps({"message": "Not found"}).encode("utf8")
            )
    elif path.startswith("/user") and method == "GET":
        assert {"Authorization": "token x_access_token"} == headers
        return utils.Response(
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


@pytest.fixture
async def ds(tmpdir):
    filepath = tmpdir / "test.db"
    ds = Datasette(
        [filepath],
        metadata={
            "plugins": {
                "datasette-auth-github": {
                    "client_id": "x_client_id",
                    "client_secret": "x_client_secret",
                    "load_orgs": ["demouser-org", "pending-org"],
                    "load_teams": [
                        "demouser-org/thetopteam",
                        "pending-org/pendingteam",
                    ],
                }
            },
            "databases": {
                "test": {
                    "queries": {"sqlite_master": "select * from sqlite_master"},
                }
            },
        },
    )
    await ds.get_database().execute_write_fn(
        lambda conn: sqlite_utils.Database(conn)["example"].insert({"name": "example"}),
        block=True,
    )
    return ds


@pytest.mark.asyncio
async def test_ds_fixture(ds):
    assert {"example"} == set(await ds.get_database().table_names())


@pytest.mark.asyncio
async def test_github_auth_start(ds):
    async with httpx.AsyncClient(app=ds.app()) as client:
        response = await client.get(
            "http://localhost/-/github-auth-start", allow_redirects=False
        )
        assert (
            "https://github.com/login/oauth/authorize?scope=read:org&client_id=x_client_id"
            == response.headers["location"]
        )


@pytest.mark.asyncio
async def test_github_auth_callback(ds, monkeypatch):
    monkeypatch.setattr(views, "http_request", stub_http_request)
    async with httpx.AsyncClient(app=ds.app()) as client:
        response = await client.get(
            "http://localhost/-/auth-callback?code=github-code-here",
            allow_redirects=False,
        )
        assert {
            "a": {
                "display": "demouser",
                "gh_id": "123",
                "gh_name": "GitHub User",
                "gh_login": "demouser",
                "gh_email": "demouser@example.com",
                "gh_orgs": ["demouser-org"],
                "gh_teams": ["demouser-org/thetopteam"],
            }
        } == ds.unsign(response.cookies["ds_actor"], "actor")
        assert "/" == response.headers["location"]

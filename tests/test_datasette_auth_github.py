from datasette.app import Datasette
import pytest
import sqlite_utils
import re


@pytest.fixture
def non_mocked_hosts():
    return ["localhost"]


@pytest.fixture
def assert_all_responses_were_requested():
    return False


@pytest.fixture
def mocked_github_api(httpx_mock):
    httpx_mock.add_response(
        url="https://github.com/login/oauth/access_token",
        method="POST",
        data="access_token=x_access_token",
    )
    for org, state in (("demouser-org", "active"), ("pending-org", "pending")):
        httpx_mock.add_response(
            url=re.compile(
                r"^https://api.github.com/orgs/{}/memberships/.*".format(org)
            ),
            json={"state": state, "role": "member"},
        )
    # Catch-all for other orgs
    httpx_mock.add_response(
        url=re.compile(r"^https://api.github.com/orgs/.*/memberships/.*"),
        status_code=403,
        json={"message": "Not a member"},
    )
    # Team lookups by ID
    for team in (
        {
            "id": 54321,
            "name": "The Top Team",
            "slug": "thetopteam",
        },
        {
            "id": 59999,
            "name": "Pending Team",
            "slug": "pendingteam",
        },
    ):
        httpx_mock.add_response(
            url=re.compile(
                r"^https://api.github.com/orgs/.*/teams/{}".format(team["slug"])
            ),
            json=team,
        )
    # Catch-all for other teams
    httpx_mock.add_response(
        url=re.compile(r"^https://api.github.com/orgs/.*/teams/.*"),
        status_code=404,
        json={"message": "Not found"},
    )
    # Team membership check
    for id, state in (("54321", "active"), ("59999", "pending")):
        httpx_mock.add_response(
            url=re.compile(
                r"^https://api.github.com/teams/{}/memberships/.*".format(id)
            ),
            json={"state": state, "role": "member"},
        )
    # Catch-all for other membership checks
    httpx_mock.add_response(
        url=re.compile(r"^https://api.github.com/teams/\d+/memberships/.*"),
        status_code=404,
        json={"message": "Not found"},
    )
    # User lookup
    httpx_mock.add_response(
        url=re.compile(r"^https://api.github.com/user.*"),
        json={
            "id": 123,
            "name": "GitHub User",
            "login": "demouser",
            "email": "demouser@example.com",
        },
    )


@pytest.fixture
async def ds(tmpdir):
    filepath = str(tmpdir / "test.db")
    filepath2 = str(tmpdir / "demouser_org_only.db")
    ds = Datasette(
        [filepath, filepath2],
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
                },
                "demouser_org_only": {"allow": {"gh_orgs": "demouser-org"}},
            },
        },
    )

    def create_tables(conn):
        sqlite_utils.Database(conn)["example"].insert({"name": "example"})

    for database in ("test", "demouser_org_only"):
        await ds.get_database(database).execute_write_fn(
            create_tables,
            block=True,
        )
    return ds


@pytest.mark.asyncio
async def test_ds_fixture(ds):
    assert {"example"} == set(await ds.get_database().table_names())


@pytest.mark.asyncio
async def test_github_auth_start(ds):
    response = await ds.client.get("/-/github-auth-start", allow_redirects=False)
    assert (
        "https://github.com/login/oauth/authorize?scope=read:org&client_id=x_client_id"
        == response.headers["location"]
    )


@pytest.mark.asyncio
async def test_github_auth_callback(ds, mocked_github_api):
    response = await ds.client.get(
        "/-/github-auth-callback?code=github-code-here",
        allow_redirects=False,
    )
    actor = ds.unsign(response.cookies["ds_actor"], "actor")["a"]
    assert {
        "display": "demouser",
        "gh_id": "123",
        "gh_name": "GitHub User",
        "gh_login": "demouser",
        "gh_email": "demouser@example.com",
        "gh_orgs": ["demouser-org"],
        "gh_teams": ["demouser-org/thetopteam"],
    }.items() <= actor.items()
    assert isinstance(actor["gh_ts"], int)
    assert "/" == response.headers["location"]


@pytest.mark.asyncio
async def test_sign_in_with_github_button(ds):
    response = await ds.client.get("/")
    fragment = '<li><a href="/-/github-auth-start">Sign in with GitHub</a></li>'
    assert fragment in response.text
    response2 = await ds.client.get(
        "/", cookies={"ds_actor": ds.sign({"a": {"display": "user"}}, "actor")}
    )
    assert fragment not in response2.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "authenticated,expected_databases",
    [
        (False, {"test"}),
        (True, {"test", "demouser_org_only"}),
    ],
)
async def test_sign_in_with_github_button(
    ds, mocked_github_api, authenticated, expected_databases
):
    cookies = {}
    if authenticated:
        auth_response = await ds.client.get(
            "/-/github-auth-callback?code=github-code-here",
            allow_redirects=False,
        )
        cookies = {"ds_actor": auth_response.cookies["ds_actor"]}
    databases = await ds.client.get("/.json", cookies=cookies)
    assert set(databases.json().keys()) == expected_databases

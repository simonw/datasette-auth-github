from datasette.app import Datasette
import pytest
import pytest_asyncio
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
        content=b"access_token=x_access_token",
        is_optional=True,
    )
    for org, state in (("demouser-org", "active"), ("pending-org", "pending")):
        httpx_mock.add_response(
            url=re.compile(
                r"^https://api.github.com/orgs/{}/memberships/.*".format(org)
            ),
            json={"state": state, "role": "member"},
            is_optional=True,
        )
    # Catch-all for other orgs
    httpx_mock.add_response(
        url=re.compile(r"^https://api.github.com/orgs/.*/memberships/.*"),
        status_code=403,
        json={"message": "Not a member"},
        is_optional=True,
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
            is_optional=True,
        )
    # Catch-all for other teams
    httpx_mock.add_response(
        url=re.compile(r"^https://api.github.com/orgs/.*/teams/.*"),
        status_code=404,
        json={"message": "Not found"},
        is_optional=True,
    )
    # Team membership check
    for id, state in (("54321", "active"), ("59999", "pending")):
        httpx_mock.add_response(
            url=re.compile(
                r"^https://api.github.com/teams/{}/memberships/.*".format(id)
            ),
            json={"state": state, "role": "member"},
            is_optional=True,
        )
    # Catch-all for other membership checks
    httpx_mock.add_response(
        url=re.compile(r"^https://api.github.com/teams/\d+/memberships/.*"),
        status_code=404,
        json={"message": "Not found"},
        is_optional=True,
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
        is_optional=True,
    )


@pytest_asyncio.fixture
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
    response = await ds.client.get("/-/github-auth-start", follow_redirects=False)
    assert (
        "https://github.com/login/oauth/authorize?scope=read:org&client_id=x_client_id"
        == response.headers["location"]
    )


@pytest.mark.asyncio
async def test_github_auth_callback(ds, mocked_github_api):
    response = await ds.client.get(
        "/-/github-auth-callback?code=github-code-here",
        follow_redirects=False,
    )
    actor = ds.unsign(response.cookies["ds_actor"], "actor")["a"]
    assert {
        "id": "github:123",
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
async def test_database_access_permissions(
    ds, mocked_github_api, authenticated, expected_databases
):
    cookies = {}
    if authenticated:
        auth_response = await ds.client.get(
            "/-/github-auth-callback?code=github-code-here",
            follow_redirects=False,
        )
        cookies = {"ds_actor": auth_response.cookies["ds_actor"]}
    databases = await ds.client.get("/.json", cookies=cookies)
    # This differs between Datasette <1.0 and >=1.0a20
    if "databases" in databases.json():
        assert set(databases.json()["databases"].keys()) == expected_databases
    else:
        assert set(databases.json().keys()) == expected_databases


@pytest.mark.asyncio
async def test_github_enterprise_host(tmpdir, httpx_mock):
    """Test that GitHub Enterprise host configuration works correctly"""
    # Mock GitHub Enterprise endpoints
    enterprise_host = "github.example.com"

    httpx_mock.add_response(
        url=f"https://{enterprise_host}/login/oauth/access_token",
        method="POST",
        content=b"access_token=enterprise_access_token",
    )

    httpx_mock.add_response(
        url=f"https://api.{enterprise_host}/user",
        json={
            "id": 456,
            "name": "Enterprise User",
            "login": "enterpriseuser",
            "email": "enterprise@example.com",
        },
    )

    httpx_mock.add_response(
        url=re.compile(
            rf"^https://api\.{re.escape(enterprise_host)}/orgs/enterprise-org/memberships/.*"
        ),
        json={"state": "active", "role": "member"},
    )

    # Create Datasette instance with GitHub Enterprise configuration
    filepath = str(tmpdir / "test.db")
    ds = Datasette(
        [filepath],
        metadata={
            "plugins": {
                "datasette-auth-github": {
                    "client_id": "enterprise_client_id",
                    "client_secret": "enterprise_client_secret",
                    "host": enterprise_host,
                    "load_orgs": ["enterprise-org"],
                }
            }
        },
    )

    def create_tables(conn):
        sqlite_utils.Database(conn)["example"].insert({"name": "example"})

    await ds.get_database().execute_write_fn(create_tables, block=True)

    # Test that the auth start URL uses the enterprise host
    response = await ds.client.get("/-/github-auth-start", follow_redirects=False)
    expected_url = f"https://{enterprise_host}/login/oauth/authorize?scope=read:org&client_id=enterprise_client_id"
    assert expected_url == response.headers["location"]

    # Test that the auth callback uses the enterprise host for API calls
    response = await ds.client.get(
        "/-/github-auth-callback?code=enterprise-code",
        follow_redirects=False,
    )

    actor = ds.unsign(response.cookies["ds_actor"], "actor")["a"]
    assert {
        "id": "github:456",
        "display": "enterpriseuser",
        "gh_id": "456",
        "gh_name": "Enterprise User",
        "gh_login": "enterpriseuser",
        "gh_email": "enterprise@example.com",
        "gh_orgs": ["enterprise-org"],
    }.items() <= actor.items()

from datasette.app import Datasette
from datasette.utils import baseconv
from datasette_auth_github.views import verify_config
from http.cookies import SimpleCookie
import inspect
import pytest
import pytest_asyncio
import sqlite_utils
import re


def datasette_with_config(files=None, config=None, **kwargs):
    # Datasette 1.0 moved plugin and permission configuration out of metadata.
    config_key = (
        "config" if "config" in inspect.signature(Datasette).parameters else "metadata"
    )
    return Datasette(files, **{config_key: config}, **kwargs)


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
    ds = datasette_with_config(
        [filepath, filepath2],
        config={
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
@pytest.mark.parametrize(
    "scheme,force_https_urls,expected_secure",
    [("http", False, False), ("https", False, True), ("http", True, True)],
    ids=["http", "https", "https-proxy"],
)
@pytest.mark.parametrize(
    "cookie_config,expected_max_age",
    [({}, 2592000), ({"login_max_age": 3600}, 3600), ({"login_max_age": None}, None)],
    ids=["default", "custom", "session-only"],
)
async def test_callback_cookie_attributes(
    mocked_github_api,
    monkeypatch,
    scheme,
    force_https_urls,
    expected_secure,
    cookie_config,
    expected_max_age,
):
    now = 1700000000
    monkeypatch.setattr("time.time", lambda: now)
    ds = datasette_with_config(
        config={
            "plugins": {
                "datasette-auth-github": {
                    "client_id": "x_client_id",
                    "client_secret": "x_client_secret",
                    **cookie_config,
                }
            }
        },
        settings={"force_https_urls": force_https_urls},
    )
    response = await ds.client.request(
        "GET",
        f"{scheme}://localhost/-/github-auth-callback?code=github-code-here",
        follow_redirects=False,
        avoid_path_rewrites=True,
    )
    assert response.status_code == 302
    cookies = SimpleCookie()
    for header in response.headers.get_list("set-cookie"):
        cookies.load(header)
    cookie = cookies["ds_actor"]
    assert cookie["httponly"] is True
    assert bool(cookie["secure"]) is expected_secure
    assert cookie["samesite"].lower() == "lax"
    assert cookie["path"] == "/"
    assert cookie["domain"] == ""
    payload = ds.unsign(cookie.value, "actor")
    assert payload["a"]["id"] == "github:123"
    if expected_max_age is None:
        assert cookie["max-age"] == ""
        assert cookie["expires"] == ""
        assert "e" not in payload
    else:
        assert cookie["max-age"] == str(expected_max_age)
        assert int(baseconv.base62.decode(payload["e"])) == now + expected_max_age


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cookie_config,max_age",
    [({}, 2592000), ({"login_max_age": 3600}, 3600), ({"login_max_age": None}, None)],
    ids=["default", "custom", "session-only"],
)
async def test_callback_cookie_expiration(
    mocked_github_api, monkeypatch, cookie_config, max_age
):
    now = 1700000000
    monkeypatch.setattr("time.time", lambda: now)
    ds = datasette_with_config(
        config={
            "plugins": {
                "datasette-auth-github": {
                    "client_id": "x_client_id",
                    "client_secret": "x_client_secret",
                    **cookie_config,
                }
            }
        }
    )
    response = await ds.client.get(
        "/-/github-auth-callback?code=github-code-here", follow_redirects=False
    )
    # Always send the cookie, even after its browser expiry, to exercise
    # Datasette's verification of the signed expiration timestamp.
    headers = {"Cookie": "ds_actor={}".format(response.cookies["ds_actor"])}
    lifetime = max_age if max_age is not None else 2592000
    now += lifetime - 1
    response = await ds.client.get("/-/actor.json", headers=headers)
    assert response.json()["actor"]["id"] == "github:123"
    now += 2
    response = await ds.client.get("/-/actor.json", headers=headers)
    if max_age is None:
        assert response.json()["actor"]["id"] == "github:123"
    else:
        assert response.json()["actor"] is None


@pytest.mark.parametrize("value", [True, False, 0, -1, "3600", 1.5])
def test_invalid_login_max_age(value):
    with pytest.raises(
        ValueError, match="^login_max_age must be a positive integer or null$"
    ):
        verify_config({"login_max_age": value})


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
    # Datasette versions expose databases as a top-level or nested dictionary,
    # or as a list of objects with a name field.
    data = databases.json()
    data = data.get("databases", data)
    names = (
        {database["name"] for database in data} if isinstance(data, list) else set(data)
    )
    assert names == expected_databases


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
    ds = datasette_with_config(
        [filepath],
        config={
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

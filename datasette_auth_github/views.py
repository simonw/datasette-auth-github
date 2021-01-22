from datasette.utils.asgi import Response
from urllib.parse import parse_qsl, urlencode
from .utils import http_request, force_list


CSS = """
<style>
body {
    font-family: "Helvetica Neue", sans-serif;
    font-size: 1rem;
}</style>
"""

DEPRECATED_KEYS = ("allow_users", "allow_orgs", "allow_teams")


def verify_config(config):
    config = config or {}
    for key in DEPRECATED_KEYS:
        assert key not in config, "{} is no longer a supported option".format(key)


async def github_auth_start(datasette):
    config = datasette.plugin_config("datasette-auth-github")
    verify_config(config)
    if config.get("load_teams"):
        scope = "read:org"
    elif config.get("load_orgs"):
        scope = "user"
    else:
        scope = "user:email"
    github_login_url = (
        "https://github.com/login/oauth/authorize?scope={}&client_id={}".format(
            scope, config["client_id"]
        )
    )
    return Response.redirect(github_login_url)


async def github_auth_callback(datasette, request, scope, receive, send):
    config = datasette.plugin_config("datasette-auth-github")
    verify_config(config)
    if not request.args.get("code"):
        return Response.html("Authentication failed, no code", status=500)

    # Exchange that code for a token
    github_response = (
        await http_request(
            "https://github.com/login/oauth/access_token",
            body=urlencode(
                {
                    "client_id": config["client_id"],
                    "client_secret": config["client_secret"],
                    "code": request.args["code"],
                }
            ).encode("utf-8"),
        )
    ).text
    parsed = dict(parse_qsl(github_response))
    # b'error=bad_verification_code&error_description=The+code+passed...'
    if parsed.get("error"):
        return Response.html(
            "{}<h1>GitHub authentication error</h1><p>{}</p><p>{}</p>".format(
                CSS, parsed["error"], parsed.get("error_description") or ""
            ),
            status=500,
        )
    access_token = parsed.get("access_token")
    if not access_token:
        return Response.html("No valid access token", status=500)

    # Use access_token to verify user
    profile_url = "https://api.github.com/user"
    try:
        profile = (
            await http_request(
                profile_url,
                headers={"Authorization": "token {}".format(access_token)},
            )
        ).json()
    except ValueError:
        return Response.html("Could not load GitHub profile", status=500)
    actor = {
        "display": profile["login"],
        "gh_id": str(profile["id"]),
        "gh_name": profile["name"],
        "gh_login": profile["login"],
        "gh_email": profile["email"],
    }
    # Optionally load orgs and/or teams
    if config.get("load_orgs"):
        load_orgs = config["load_orgs"]
        gh_orgs = []
        for org in force_list(load_orgs):
            url = "https://api.github.com/orgs/{}/memberships/{}".format(
                org, profile["login"]
            )
            response = await http_request(
                url, headers={"Authorization": "token {}".format(access_token)}
            )
            if response.status_code == 200 and response.json()["state"] == "active":
                gh_orgs.append(org)
        actor["gh_orgs"] = gh_orgs
    if config.get("load_teams"):
        load_teams = config["load_teams"]
        gh_teams = []
        for team in force_list(load_teams):
            org_slug, _, team_slug = team.partition("/")
            # Figure out the team_id
            lookup_url = "https://api.github.com/orgs/{}/teams/{}".format(
                org_slug, team_slug
            )
            response = await http_request(
                lookup_url,
                headers={"Authorization": "token {}".format(access_token)},
            )
            if response.status_code == 200:
                team_id = response.json()["id"]
            else:
                continue
            # Now check if user is an active member of the team:
            team_membership_url = (
                "https://api.github.com/teams/{}/memberships/{}".format(
                    team_id, profile["login"]
                )
            )
            response = await http_request(
                team_membership_url,
                headers={"Authorization": "token {}".format(access_token)},
            )
            if response.status_code == 200 and response.json()["state"] == "active":
                gh_teams.append(team)
        actor["gh_teams"] = gh_teams

    # Set a signed cookie and redirect to homepage
    response = Response.redirect("/")
    response.set_cookie("ds_actor", datasette.sign({"a": actor}, "actor"))
    return response

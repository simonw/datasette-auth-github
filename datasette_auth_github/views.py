from datasette.utils.asgi import Response
from urllib.parse import parse_qsl
from .utils import load_orgs_and_teams
import httpx


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


async def response_error(datasette, error):
    return Response.html(
        await datasette.render_template(
            "datasette_auth_github_error.html", {"error": error}
        ),
        status=500,
    )


async def github_auth_callback(datasette, request, scope, receive, send):
    config = datasette.plugin_config("datasette-auth-github")
    verify_config(config)
    if not request.args.get("code"):
        return await response_error(datasette, "Authentication failed, no code")

    # Exchange that code for a token
    async with httpx.AsyncClient() as client:
        github_response = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
                "code": request.args["code"],
            },
        )
    parsed = dict(parse_qsl(github_response.text))
    # b'error=bad_verification_code&error_description=The+code+passed...'
    if parsed.get("error"):
        return await response_error(
            datasette, parsed["error"] + ": " + (parsed.get("error_description") or "")
        )
    access_token = parsed.get("access_token")
    if not access_token:
        return await response_error(datasette, "No valid access token")

    # Use access_token to verify user
    profile_url = "https://api.github.com/user"
    try:
        async with httpx.AsyncClient() as client:
            profile = (
                await client.get(
                    profile_url,
                    headers={"Authorization": "token {}".format(access_token)},
                )
            ).json()
    except ValueError:
        return await response_error(datasette, "Could not load GitHub profile")
    actor = {
        "display": profile["login"],
        "gh_id": str(profile["id"]),
        "gh_name": profile["name"],
        "gh_login": profile["login"],
        "gh_email": profile["email"],
    }
    extras = await load_orgs_and_teams(config, profile, access_token)
    actor.update(extras)

    # Set a signed cookie and redirect to homepage
    response = Response.redirect("/")
    response.set_cookie("ds_actor", datasette.sign({"a": actor}, "actor"))
    return response

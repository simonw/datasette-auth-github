import httpx
import time


async def load_orgs_and_teams(config, profile, access_token):
    store_timestamp = False
    extras = {}
    if config.get("load_orgs"):
        load_orgs = config["load_orgs"]
        gh_orgs = []
        for org in force_list(load_orgs):
            url = "https://api.github.com/orgs/{}/memberships/{}".format(
                org, profile["login"]
            )
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    url, headers={"Authorization": "token {}".format(access_token)}
                )
            if response.status_code == 200 and response.json()["state"] == "active":
                gh_orgs.append(org)
        extras["gh_orgs"] = gh_orgs
        store_timestamp = True
    if config.get("load_teams"):
        load_teams = config["load_teams"]
        gh_teams = []
        for team in force_list(load_teams):
            org_slug, _, team_slug = team.partition("/")
            # Figure out the team_id
            lookup_url = "https://api.github.com/orgs/{}/teams/{}".format(
                org_slug, team_slug
            )
            async with httpx.AsyncClient() as client:
                response = await client.get(
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
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    team_membership_url,
                    headers={"Authorization": "token {}".format(access_token)},
                )
            if response.status_code == 200 and response.json()["state"] == "active":
                gh_teams.append(team)
        extras["gh_teams"] = gh_teams
        store_timestamp = True

    if store_timestamp:
        extras["gh_ts"] = int(time.time())

    return extras


def force_list(value):
    if isinstance(value, str):
        return [value]
    return value

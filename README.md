# datasette-auth-github

[![PyPI](https://img.shields.io/pypi/v/datasette-auth-github.svg)](https://pypi.org/project/datasette-auth-github/)
[![Changelog](https://img.shields.io/github/v/release/simonw/datasette-auth-github?include_prereleases&label=changelog)](https://github.com/simonw/datasette-auth-github/releases)
[![Tests](https://github.com/simonw/datasette-auth-github/workflows/Test/badge.svg)](https://github.com/simonw/datasette-auth-github/actions?query=workflow%3ATest)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/simonw/datasette-auth-github/blob/main/LICENSE)

Datasette plugin that authenticates users against GitHub.

The new [0.13a1 alpha release](https://github.com/simonw/datasette-auth-github/releases/tag/0.13a0) requires [Datasette 0.51](https://datasette.readthedocs.io/en/latest/changelog.html#v0-51) or later.

<!-- toc -->

- [Setup instructions](#setup-instructions)
- [The authenticated actor](#the-authenticated-actor)
- [Restricting access to specific users](#restricting-access-to-specific-users)
- [Restricting access to specific GitHub organizations or teams](#restricting-access-to-specific-github-organizations-or-teams)

<!-- tocstop -->

## Setup instructions

* Install the plugin: `datasette install datasette-auth-github`
* Create a GitHub OAuth app: https://github.com/settings/applications/new
* Set the Authorization callback URL to `http://127.0.0.1:8001/-/github-auth-callback`
* Create a `metadata.json` file with the following structure:

```json
{
    "title": "datasette-auth-github demo",
    "plugins": {
        "datasette-auth-github": {
            "client_id": {"$env": "GITHUB_CLIENT_ID"},
            "client_secret": {"$env": "GITHUB_CLIENT_SECRET"}
        }
    }
}
```

Now you can start Datasette like this, passing in the secrets as environment variables:

    $ GITHUB_CLIENT_ID=XXX GITHUB_CLIENT_SECRET=YYY datasette \
        fixtures.db -m metadata.json

Note that hard-coding secrets in `metadata.json` is a bad idea as they will be visible to anyone who can navigate to `/-/metadata`. Instead, we use Datasette's mechanism for [adding secret plugin configuration options](https://datasette.readthedocs.io/en/latest/plugins.html#secret-configuration-values).

By default anonymous users will still be able to interact with Datasette. If you wish all users to have to sign in with a GitHub account first, add this to your ``metadata.json``:

```json
{
    "allow": {
        "id": "*"
    },
    "plugins": {
        "datasette-auth-github": {
            "...": "..."
        }
    }
}
```
## The authenticated actor

Visit `/-/actor` when signed in to see the shape of the authenticated actor. It should look something like this:

```json
{
    "actor": {
        "display": "simonw",
        "gh_id": "9599",
        "gh_name": "Simon Willison",
        "gh_login": "simonw",
        "gh_email": "...",
        "gh_orgs": [
            "dogsheep",
            "datasette-project"
        ],
        "gh_teams": [
            "dogsheep/test"
        ],
        "gh_ts": 1611434081
    }
}
```

The `gh_orgs`, `gh_teams` and `gh_ts` properties will only be present if you use the `load_teams` or `load_orgs` configuration settings, documented below.

## Restricting access to specific users

You can use Datasette's [permissions mechanism](https://datasette.readthedocs.io/en/stable/authentication.html) to specify which user or users are allowed to access your instance. Here's how to restrict access to just GitHub user `simonw`:

```json
{
    "allow": {
        "gh_login": "simonw"
    },
    "plugins": {
        "datasette-auth-github": {
            "...": "..."
        }
    }
}
```

This `"allow"` block can be positioned at the database, table or query level instead: see [Configuring permissions in metadata.json](https://datasette.readthedocs.io/en/stable/authentication.html#configuring-permissions-in-metadata-json) for details.

## Restricting access to specific GitHub organizations or teams

You can also restrict access to users who are members of a specific GitHub organization.

You'll need to configure the plugin to check if the user is a member of that organization when they first sign in. You can do that using the `"load_orgs"` plugin configuration option.

Then you can use `"allow": {"gh_orgs": [...]}` to specify which organizations are allowed access.

```json
{
    "plugins": {
        "datasette-auth-github": {
            "...": "...",
            "load_orgs": ["your-organization"]
        }
    },
    "allow": {
        "gh_orgs": "your-organization"
    }
}
```

If your organization is [arranged into teams](https://help.github.com/en/articles/organizing-members-into-teams) you can restrict access to a specific team like this:

```json
{
    "plugins": {
        "datasette-auth-github": {
            "...": "...",
            "load_teams": [
                "your-organization/staff",
                "your-organization/engineering",
            ]
        }
    },
    "allows": {
        "gh_team": "your-organization/engineering"
    }
}
```

## Configuring a timeout for checking GitHub teams and organizations

The first time a user signs in, their current relevant teams and organizations are written to their signed `ds_actor` cookie. This helps avoid making additional permission checking API calls to GitHub every time that user performs another action on the site.

If a user is removed from a team or organization it is important for them to lose access to resources in Datasette as well. The plugin defaults to re-confirming their membership of teams and organizations every five minutes, so if a user is removed from a team or organization they should lose access to any associated Datasette resources within five minutes of the change being applied on GitHub.

You can configure this timeout is seconds using the `membership_cache_ttl` setting in `metadata.json`, like this:

```json
{
    "plugins": {
        "datasette-auth-github": {
            "...": "...",
            "membership_cache_ttl": 60
        }
    }
}
```

You should consider [GitHub's API rate limits](https://docs.github.com/en/developers/apps/rate-limits-for-github-apps) when changing this setting.

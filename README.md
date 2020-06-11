# datasette-auth-github

[![PyPI](https://img.shields.io/pypi/v/datasette-auth-github.svg)](https://pypi.org/project/datasette-auth-github/)
[![CircleCI](https://circleci.com/gh/simonw/datasette-auth-github.svg?style=svg)](https://circleci.com/gh/simonw/datasette-auth-github)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/simonw/datasette-auth-github/blob/master/LICENSE)

Datasette plugin that authenticates users against GitHub.

This requires [Datasette 0.44](https://datasette.readthedocs.io/en/latest/changelog.html#v0-44) or later.

## Setup instructions

* Install the plugin - `pip install datasette-auth-github`
* Create a GitHub OAuth app: https://github.com/settings/applications/new
* Set the Authorization callback URL to `http://127.0.0.1:8001/-/auth-callback`
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

Note that hard-coding secrets in `metadata.json` is a bad idea as they will be visible to anyone who can navigate to `/-/metadata`. Instead, we use a new mechanism for [adding secret plugin configuration options](https://datasette.readthedocs.io/en/latest/plugins.html#secret-configuration-values).

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

## Restricting access to specific users

You can use Datasette's [permissions mechanism](https://datasette.readthedocs.io/en/stable/authentication.html) to specify which user or users are allowed to access your instance. Here's how to restrict access to just GitHub user `simonw`:

```json
{
    "allow": {
        "gh_user": "simonw"
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
        "gh_org": "your-organization"
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
    "allow": {
        "gh_team": "your-organization/engineering"
    }
}
```

## Automatic log in

Assuming you are requiring authentication (the default) Datasette will redirect users to GitHub to sign in. If the user has previously authenticated with GitHub they will be redirected back again automatically, providing an instant sign-on experience.

If you would rather they saw a "You are logged out" screen with a button first, you can change this behaviour by adding the "disable_auto_login" setting to your configuration:

```json
{
    "plugins": {
        "datasette-auth-github": {
            "client_id": "...",
            "client_secret": "...",
            "disable_auto_login": true
        }
    }
}
```

## Cookie expiration

The cookies set by this plugin default to expiring after an hour. Users with expired cookies will be automatically redirected back through GitHub to log in, so they are unlikely to notice that their cookies have expired.

You can change the cookie expiration policy in seconds using the `cookie_ttl` setting. Here's how to increase that timeout to 24 hours:

```json
{
    "plugins": {
        "datasette-auth-github": {
            "client_id": "...",
            "client_secret": "...",
            "cookie_ttl": 86400
        }
    }
}
```

## Forced cookie expiration

If you are using GitHub organizations or teams with this plugin, you need to be aware that users may continue to hold valid cookies even after they have been removed from a team or organization - generally for up to an hour unless you have changed the `cookie_ttl`.

If you need to revoke access to your instance immediately, you can do so using the `cookie_version` setting. Simply modify your metadata to add a new value for `cookie_version` and restart or redeploy your Datasette instance:

```json
{
    "plugins": {
        "datasette-auth-github": {
            "client_id": "...",
            "client_secret": "...",
            "cookie_version": 2
        }
    }
}
```

All existing cookies will be invalidated. Users who are still members of the organization or team will be able to sign in again - and in fact may be signed in automatically. Users who have been removed from the organization or team will lose access to the Datasette instance.

### cacheable_prefixes

By default, the middleware marks all returned responses as `cache-control: private`. This is to ensure that content which was meant to be private to an individual user is not accidentally stored and re-transmitted by any intermediary proxying caches.

This means even static JavaScript and CSS assets will not be cached by the user's browser, which can have a negative impact on performance.

You can specify path prefixes that should NOT be marked as `cache-control: private` using the `cacheable_prefixes` constructor argument:

```python
app = GitHubAuth(
    asgi_app,
    client_id="github_client_id",
    client_secret="github_client_secret",
    require_auth=True,
    cacheable_prefixes=["/static/"],
)
```

Now any files within the `/static/` directory will not have the `cache-control: private` header added by the middleware.

# datasette-auth-github

[![PyPI](https://img.shields.io/pypi/v/datasette-auth-github.svg)](https://pypi.org/project/datasette-auth-github/)
[![CircleCI](https://circleci.com/gh/simonw/datasette-auth-github.svg?style=svg)](https://circleci.com/gh/simonw/datasette-auth-github)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/simonw/datasette-auth-github/blob/master/LICENSE)

Datasette plugin and ASGI middleware that authenticates users against GitHub.

This requires [Datasette 0.29](https://datasette.readthedocs.io/en/stable/changelog.html#v0-29) or later.

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

By default, the plugin will require users to sign in before they can interact with Datasette - but it will allow in anyone with a GitHub account.

If you want anonymous users to be able to view Datasette without signing in, you can add the `"require_auth": false` setting to your configuration:

```json
{
    "plugins": {
        "datasette-auth-github": {
            "client_id": ...,
            "require_auth": false
        }
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

## Restricting access to specific users

By default the plugin will allow any GitHub user to log in. You can restrict allowed users to a specific list using the `allow_users` configuration option:

```json
{
    "plugins": {
        "datasette-auth-github": {
            "client_id": "...",
            "client_secret": "...",
            "allow_users": ["simonw"]
        }
    }
}
```
You can list one or more GitHub usernames here.

## Restricting access to specific GitHub organizations or teams

You can also restrict access to users who are members of a specific GitHub organization:

```json
{
    "plugins": {
        "datasette-auth-github": {
            "client_id": "...",
            "client_secret": "...",
            "allow_orgs": ["datasette-project"]
        }
    }
}
```

If your organization is [arranged into teams](https://help.github.com/en/articles/organizing-members-into-teams) you can restrict access to a specific team like this:

```json
{
    "plugins": {
        "datasette-auth-github": {
            "client_id": "...",
            "client_secret": "...",
            "allow_teams": ["your-organization/engineering"]
        }
    }
}
```

## Using this with the 'datasette publish' command

`allow_orgs`, `allow_users` and `allow_teams` can both be single strings rather than lists. This means you can publish data and configure the plugin entirely from the command-line like so:

    $ datasette publish nowv1 fixtures.db \
        --alias datasette-auth-demo \
        --install=datasette-auth-github \
        --plugin-secret datasette-auth-github client_id 86e397f7fd7a54d26a3a \
        --plugin-secret datasette-auth-github client_secret ... \
        --plugin-secret datasette-auth-github allow_user simonw

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

## Using this as ASGI middleware without Datasette

While `datasette-auth-github` is designed to be used as a [Datasette plugin](https://datasette.readthedocs.io/en/stable/plugins.html), it can also be used as regular ASGI middleware to add GitHub authentication to any ASGI application.

Here's how to do that:

```python
from datasette_auth_github import GitHubAuth
from your_asgi_app import asgi_app


app = GitHubAuth(
    asgi_app,
    client_id="github_client_id",
    client_secret="github_client_secret",
    require_auth=True, # Defaults to False
    # Other options:
    # cookie_ttl=24 * 60 * 60,
    # disable_auto_login=True,
    # allow_users=["simonw"],
    # allow_orgs=["my-org"],
    # allow_teams=["my-org/engineering"],
)
```

The keyword arguments work in the same way as the Datasette plugin settings documented above.

There's one key difference: when used as a plugin, `require_auth` defaults to True. If you are wrapping your own application using the middleware the default behaviour is to allow anonymous access - you need to explicitly set the `require_auth=True` keyword argument to change this behaviour.

Once wrapped in this way, your application will redirect users to GitHub to authenticate if they are not yet signed in. Authentication is recorded using a signed cookie.

The middleware adds a new `"auth"` key to the scope containing details of the signed-in user, which is then passed to your application. The contents of the `scope["auth"]` key will look like this:

```json
{
    "id": "1234 (their GitHub user ID)",
    "name": "Their Display Name",
    "username": "their-github-username",
    "email": "their-github@email-address.com",
    "ts": 1562602415
}
```
The `"ts"` value is an integer `time.time()` timestamp representing when the user last signed in.

If the user is not signed in (and you are not using required authentication) the `"auth"` scope key will be set to `None`.

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

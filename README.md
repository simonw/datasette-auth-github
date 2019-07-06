# datasette-auth-github

[![PyPI](https://img.shields.io/pypi/v/datasette-auth-github.svg)](https://pypi.org/project/datasette-auth-github/)
[![CircleCI](https://circleci.com/gh/simonw/datasette-auth-github.svg?style=svg)](https://circleci.com/gh/simonw/datasette-auth-github)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/simonw/datasette-auth-github/blob/master/LICENSE)

Datasette plugin that authenticates users against GitHub.

This requires datasette master - it uses unreleased plugin hooks.

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

By default, the plugin will redirect signed-out users directly to GitHub.

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

## Restricting access to specific GitHub organizations

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

# datasette-auth-github

Datasette plugin that authenticates users against GitHub.

This is a very early alpha! Don't use this yet.

For example, it leaks your `client_secret` in `/-/metadata.json` in a way that is visible to any user who is logged in. This is bad!

Usage instructions:

* Install the plugin
* Create a GitHub OAuth app: https://github.com/settings/applications/new
* Set the Authorization callback URL to `http://127.0.0.1:8001/-/auth-callback`
* Create a `metadata.json` file with the following structure:

```json
{
    "title": "datasette-auth-github demo",
    "plugins": {
        "datasette-auth-github": {
            "client_id": "your-github-client-id",
            "client_secret": "your-github-client-secret"
        }
    }
}
```
Now you can start Datasette like this:

    $ datasette fixtures.db -m metadata.json

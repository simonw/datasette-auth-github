from datasette import hookimpl
from .views import github_auth_start, github_auth_callback


@hookimpl
def register_routes():
    return [
        (r"^/-/github-auth-start$", github_auth_start),
        (r"^/-/github-auth-callback$", github_auth_callback),
    ]


@hookimpl
def menu_links(datasette, actor):
    if not actor:
        return [
            {
                "href": datasette.urls.path("/-/github-auth-start"),
                "label": "Sign in with GitHub",
            },
        ]

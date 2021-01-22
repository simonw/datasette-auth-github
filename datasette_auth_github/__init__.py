from datasette import hookimpl
from .views import github_auth_start, github_auth_callback


@hookimpl
def register_routes():
    return [
        (r"^/-/github-auth-start$", github_auth_start),
        (r"^/-/auth-callback$", github_auth_callback),
    ]

from datasette import hookimpl
from datasette import actor_auth_cookie
from functools import wraps
import time
from sqlite_utils.db import DEFAULT
from .views import github_auth_start, github_auth_callback


DEFAULT_TTL = 5 * 60


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


@hookimpl
def actor_from_request(datasette, request):
    actor = actor_auth_cookie.actor_from_request(datasette, request)
    if actor is None or "gh_ts" not in actor:
        return actor
    # Check that "gh_ts" has not expired
    config = datasette.plugin_config("datasette-auth-github") or {}
    ttl = config.get("membership_cache_ttl") or DEFAULT_TTL
    gh_ts = actor["gh_ts"]
    expires_at = gh_ts + ttl
    if expires_at < int(time.time()):
        # It expired! Load memberships from the API again
        assert False


@hookimpl
def asgi_wrapper(datasette):
    def wrap_with_actor_reset(app):
        @wraps(app)
        async def reset_actor_cookie_if_necessary(scope, recieve, send):
            new_actor = None

            def reset_actor_cookie(actor):
                nonlocal new_actor
                new_actor = actor

            scope = dict(scope, reset_actor_cookie=reset_actor_cookie)

            async def wrapped_send(event):
                if event["type"] == "http.response.start":
                    # Set new actor cookie, if needed
                    nonlocal new_actor
                    if new_actor:
                        ds_actor = datasette.sign({"a": new_actor}, "actor")
                        new_headers = event.get("headers") or []
                        new_headers.append(
                            (
                                b"set-cookie",
                                "ds_actor={}; Path=/".format(ds_actor).encode("utf-8"),
                            )
                        )
                        event = {
                            "type": event["type"],
                            "status": event["status"],
                            "headers": new_headers,
                        }
                await send(event)

            await app(scope, recieve, wrapped_send)

        return reset_actor_cookie_if_necessary

    return wrap_with_actor_reset

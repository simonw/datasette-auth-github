import hashlib
import json
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qsl, urlencode

from .utils import (
    BadSignature,
    Signer,
    force_list,
    send_html,
    cookies_from_scope,
    http_request,
)

from .github_auth import GitHubAuth

LOGIN_CSS = """
<style>
body {
    font-family: "Helvetica Neue", sans-serif;
    font-size: 1rem;
}</style>
"""

LOGIN_BUTTON = """
<a href="{}" target="_top" style="
  text-decoration: none;
  font-family: helvetica;
  font-weight: bold;
  color: #ddd;
  background-color: black;
  height: 30px;
  display: inline-block;
  padding: 1px 12px 0 0;
  border-radius: 5px;
">
<svg xmlns="http://www.w3.org/2000/svg"
aria-label="Google" role="img"
viewBox="0 0 512 512" style="
  width: 30px; vertical-align: middle; border-right:0.5px solid #aaa;"
><rect
width="512" height="512" rx="15%" fill="#1B1817"/>
<path fill="#fff" d="M335 499c14 0 12 17 12 17H165s-2-17 12-17c13 0 16-6 16-12l-1-50c-71 16-86-28-86-28-12-30-28-37-28-37-24-16 1-16 1-16 26 2 40 26 40 26 22 39 59 28 74 22 2-17 9-28 16-35-57-6-116-28-116-126 0-28 10-51 26-69-3-6-11-32 3-67 0 0 21-7 70 26 42-12 86-12 128 0 49-33 70-26 70-26 14 35 6 61 3 67 16 18 26 41 26 69 0 98-60 120-117 126 10 8 18 24 18 48l-1 70c0 6 3 12 16 12z"/>
</svg>
<span style="padding-left: 5px;">Log in with Google</span>
</a>
"""


class GoogleAuth(GitHubAuth):
    provider = 'Google'

    def __init__(
        self,
        app,
        client_id,
        client_secret,
        redirect_uri,
        require_auth=False,
        cookie_ttl=60 * 60,
        cookie_version=None,
        disable_auto_login=False,
        allow_users=None,
        allow_domains=None,
        cacheable_prefixes=None,
    ):
        self.redirect_uri = redirect_uri
        self.allow_domains = allow_domains
        super().__init__(
            app,
            client_id,
            client_secret,
            require_auth=require_auth,
            cookie_ttl=cookie_ttl,
            cookie_version=cookie_version,
            disable_auto_login=disable_auto_login,
            allow_users=allow_users,
            cacheable_prefixes=cacheable_prefixes,
        )

    def oauth_scope(self):
        """TODO: refer the Google Sign-In section here and resolve 
        to the frequent options.
        https://developers.google.com/identity/protocols/googlescopes
        https://developers.google.com/identity/sign-in/web/backend-auth
        https://developers.google.com/identity/protocols/OAuth2WebServer#userconsentprompt
        https://stackoverflow.com/questions/55448883/how-i-can-get-user-info-profile-from-google-api
        """
        return "profile email"

    @property
    def login_url(self):
        return (
            "https://accounts.google.com/o/oauth2/v2/auth?scope={}&client_id={}&redirect_uri={}&response_type=code".format(
                self.oauth_scope(), self.client_id, self.redirect_uri
            )
        )

    async def user_is_allowed(self, auth, access_token):
        # If no permissions set at all, user is allowed
        if (
            self.allow_users is None
            and self.allow_domains is None
        ):
            return True
        if self.allow_users is not None:
            # Check if the user is in that list
            if auth["username"] in force_list(self.allow_users):
                return True
        if self.allow_domains is not None:
            domain = auth["email"].split("@")[-1]
            if domain in self.allow_domains:
                return True

        return False

    async def exchange_code_for_token(self, code):
        response = (
            await self.http_request(
                "https://www.googleapis.com/oauth2/v4/token",
                body=urlencode(
                    {
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "redirect_uri": self.redirect_uri,
                        "code": code,
                        "grant_type": 'authorization_code'
                    }
                ).encode("utf-8"),
            )
        )
        return response.json()

    async def fetch_auth_for_token(self, access_token):
        # use with id_token  "https://oauth2.googleapis.com/tokeninfo?id_token={}"
        # with access_token, "https://www.googleapis.com/plus/v1/people/me?access_token={}" 
        # TODO: make `access_token` mechanism work preferably
        profile_url = "https://oauth2.googleapis.com/tokeninfo?id_token={}".format(access_token)
        try:
            profile = (await self.http_request(profile_url)).json()
        except ValueError:
            return {}
        return {
            "id": '',
            "name": profile["name"],
            "username": profile["name"],
            "email": profile["email"],
        }

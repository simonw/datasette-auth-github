import asyncio
import json
import urllib.request


async def http_request(url, body=None, headers=None):
    "Performs POST if body provided, GET otherwise."
    headers = headers or {}

    def _request():
        try:
            message = urllib.request.urlopen(urllib.request.Request(url, body, headers))
            response_body = message.read()
            return message.status, tuple(message.headers.raw_items()), response_body
        except urllib.error.HTTPError as http_error:
            return http_error.status, tuple(), ""

    loop = asyncio.get_event_loop()
    status_code, headers, body = await loop.run_in_executor(None, _request)
    return Response(status_code, headers, body)


class Response:
    "Wrapper class making HTTP responses easier to work with"

    def __init__(self, status_code, headers, body):
        self.status_code = status_code
        self.headers = headers
        self.body = body

    def json(self):
        return json.loads(self.text)

    @property
    def text(self):
        # Should decode according to Content-Type, for the moment assumes utf8
        if isinstance(self.body, bytes):
            return self.body.decode("utf-8")
        else:
            return self.body


def force_list(value):
    if isinstance(value, str):
        return [value]
    return value

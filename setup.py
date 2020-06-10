from setuptools import setup
import os

VERSION = "0.12"


def get_long_description():
    with open(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "README.md"),
        encoding="utf8",
    ) as fp:
        return fp.read()


setup(
    name="asgi-auth-github",
    description="ASGI middleware that authenticates users against GitHub",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    author="Simon Willison",
    url="https://github.com/simonw/asgi-auth-github",
    license="Apache License, Version 2.0",
    version=VERSION,
    packages=["asgi_auth_github"],
    extras_require={
        "test": ["pytest", "pytest-asyncio", "asgiref~=3.1.2"]
    },
    tests_require=["asgi-auth-github[test]"],
    package_data={"asgi_auth_github": ["templates/*.html"]},
)

from setuptools import setup
import os

VERSION = "0.13"


def get_long_description():
    with open(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "README.md"),
        encoding="utf8",
    ) as fp:
        return fp.read()


setup(
    name="datasette-auth-github",
    description="Datasette plugin and ASGI middleware that authenticates users against GitHub",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    author="Simon Willison",
    url="https://github.com/simonw/datasette-auth-github",
    license="Apache License, Version 2.0",
    version=VERSION,
    packages=["datasette_auth_github"],
    entry_points={"datasette": ["auth_github = datasette_auth_github"]},
    install_requires=["datasette>=0.51"],
    extras_require={
        "test": [
            "datasette",
            "pytest",
            "pytest-asyncio",
            "sqlite-utils",
            "pytest-httpx",
        ]
    },
    tests_require=["datasette-auth-github[test]"],
    package_data={"datasette_auth_github": ["templates/*.html"]},
)

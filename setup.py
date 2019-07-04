from setuptools import setup
import os

VERSION = "0.1"


def get_long_description():
    with open(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "README.md"),
        encoding="utf8",
    ) as fp:
        return fp.read()


setup(
    name="datasette-auth-github",
    description="Datasette plugin that authenticates users against GitHub",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    author="Simon Willison",
    url="https://github.com/simonw/datasette-auth-github",
    license="Apache License, Version 2.0",
    version=VERSION,
    py_modules=["datasette_auth_github"],
    entry_points={"datasette": ["auth_github = datasette_auth_github"]},
    extras_require={
        "test": ["datasette", "pytest", "pytest-asyncio", "asgiref~=3.1.2"]
    },
    tests_require=["datasette-auth-github[test]"],
)

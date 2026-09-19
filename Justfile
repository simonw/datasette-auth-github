set positional-arguments

test *args:
    uv run --isolated --with 'datasette<1.0' -- python -m pytest
    uv run --isolated --with 'datasette>=1.0a20' -- python -m pytest

set positional-arguments

test *args:
    uv run --isolated --with 'datasette<1.0' --with-editable '.[test]' -- python -m pytest
    uv run --isolated --with 'datasette>=1.0a20' --with-editable '.[test]' -- python -m pytest

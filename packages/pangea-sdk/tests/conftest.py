from __future__ import annotations

import logging
from collections.abc import Iterable

import pytest
from pytest_asyncio import is_async_test

logging.getLogger("pangea").setLevel(logging.DEBUG)


# Add `pytest.mark.asyncio()` to all async tests.
def pytest_collection_modifyitems(items: Iterable[pytest.Function]) -> None:
    pytest_asyncio_tests = (item for item in items if is_async_test(item))
    session_scope_marker = pytest.mark.asyncio(loop_scope="session")
    for async_test in pytest_asyncio_tests:
        async_test.add_marker(session_scope_marker, append=False)

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator
from datetime import datetime

import pytest

from pangea import PangeaConfig
from pangea.asyncio.services import AuthZAsync
from pangea.services import AuthZ
from pangea.services.authz import (
    BulkCheckRequestItem,
    BulkCheckResult,
    CheckResult,
    Resource,
    Subject,
    Tuple,
    TupleCreateResult,
)

from ..utils import assert_matches_type

base_url = os.environ.get("TEST_API_BASE_URL", "http://127.0.0.1:4010")


@pytest.fixture(scope="session")
def client(request: pytest.FixtureRequest) -> Iterator[AuthZ]:
    yield AuthZ(token="my_api_token", config=PangeaConfig(base_url_template=base_url))


@pytest.fixture(scope="session")
async def async_client(request: pytest.FixtureRequest) -> AsyncIterator[AuthZAsync]:
    async with AuthZAsync(token="my_api_token", config=PangeaConfig(base_url_template=base_url)) as client:
        yield client


class TestAuthZ:
    def test_tuple_create(self, client: AuthZ) -> None:
        response = client.tuple_create(
            tuples=[
                Tuple(
                    resource=Resource(type="file", id="file_1"),
                    relation="read",
                    subject=Subject(type="user", id="user_1", action="read"),
                    expires_at=datetime(2099, 9, 21, 17, 24, 33, 105000),
                    attributes={"foo": "bar"},
                )
            ]
        )
        assert response.status == "Success"
        assert response.result
        assert_matches_type(TupleCreateResult, response.result, path=["response"])

    def test_check(self, client: AuthZ) -> None:
        response = client.check(
            resource=Resource(type="file", id="file_1"),
            action="read",
            subject=Subject(type="user", id="user_1", action="read"),
        )
        assert response.status == "Success"
        assert response.result
        assert_matches_type(CheckResult, response.result, path=["response"])

    def test_bulk_check(self, client: AuthZ) -> None:
        response = client.bulk_check(
            checks=[
                BulkCheckRequestItem(
                    resource=Resource(type="file", id="file_1"),
                    action="read",
                    subject=Subject(type="user", id="user_1", action="read"),
                )
            ]
        )
        assert response.status == "Success"
        assert response.result
        assert_matches_type(BulkCheckResult, response.result, path=["response"])


class TestAuthZAsync:
    async def test_tuple_create(self, async_client: AuthZAsync) -> None:
        response = await async_client.tuple_create(
            tuples=[
                Tuple(
                    resource=Resource(type="file", id="file_1"),
                    relation="read",
                    subject=Subject(type="user", id="user_1", action="read"),
                    expires_at=datetime(2099, 9, 21, 17, 24, 33, 105000),
                    attributes={"foo": "bar"},
                )
            ]
        )
        assert response.status == "Success"
        assert response.result
        assert_matches_type(TupleCreateResult, response.result, path=["response"])

    async def test_check(self, async_client: AuthZAsync) -> None:
        response = await async_client.check(
            resource=Resource(type="file", id="file_1"),
            action="read",
            subject=Subject(type="user", id="user_1", action="read"),
        )
        assert response.status == "Success"
        assert response.result
        assert_matches_type(CheckResult, response.result, path=["response"])

    async def test_bulk_check(self, async_client: AuthZAsync) -> None:
        response = await async_client.bulk_check(
            checks=[
                BulkCheckRequestItem(
                    resource=Resource(type="file", id="file_1"),
                    action="read",
                    subject=Subject(type="user", id="user_1", action="read"),
                )
            ]
        )
        assert response.status == "Success"
        assert response.result
        assert_matches_type(BulkCheckResult, response.result, path=["response"])

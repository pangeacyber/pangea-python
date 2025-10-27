from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator

import pytest

from pangea import PangeaConfig
from pangea.asyncio.services import RedactAsync
from pangea.services import Redact

base_url = os.environ.get("TEST_API_BASE_URL", "http://127.0.0.1:4010")


@pytest.fixture(scope="session")
def client(request: pytest.FixtureRequest) -> Iterator[Redact]:
    yield Redact(token="my_api_token", config=PangeaConfig(base_url_template=base_url))


@pytest.fixture(scope="session")
async def async_client(request: pytest.FixtureRequest) -> AsyncIterator[RedactAsync]:
    async with RedactAsync(token="my_api_token", config=PangeaConfig(base_url_template=base_url)) as client:
        yield client


UNREDACT_FIXTURES = [
    "redacted_data",
    {"redacted_data": "redacted_data"},
    [0, 1, 2],
]


class TestRedact:
    def test_unredact(self, client: Redact) -> None:
        for redacted_data in UNREDACT_FIXTURES:
            response = client.unredact(redacted_data, "fpe_context")
            assert response.status == "Success"
            assert response.result


class TestShareAsync:
    async def test_update(self, async_client: RedactAsync) -> None:
        for redacted_data in UNREDACT_FIXTURES:
            response = await async_client.unredact(redacted_data, "fpe_context")
            assert response.status == "Success"
            assert response.result

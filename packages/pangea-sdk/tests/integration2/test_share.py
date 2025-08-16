from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator

import pytest

from pangea import PangeaConfig
from pangea.asyncio.services import ShareAsync
from pangea.services import Share
from pangea.services.share.share import UpdateResult

from ..utils import assert_matches_type

base_url = os.environ.get("TEST_API_BASE_URL", "http://127.0.0.1:4010")


@pytest.fixture(scope="session")
def client(request: pytest.FixtureRequest) -> Iterator[Share]:
    yield Share(token="my_api_token", config=PangeaConfig(base_url_template=base_url))


@pytest.fixture(scope="session")
async def async_client(request: pytest.FixtureRequest) -> AsyncIterator[ShareAsync]:
    async with ShareAsync(token="my_api_token", config=PangeaConfig(base_url_template=base_url)) as client:
        yield client


class TestShare:
    def test_update(self, client: Share) -> None:
        response = client.update()
        assert response.status == "Success"
        assert response.result
        assert_matches_type(UpdateResult, response.result, path=["response"])


class TestShareAsync:
    async def test_update(self, async_client: ShareAsync) -> None:
        response = await async_client.update()
        assert response.status == "Success"
        assert response.result
        assert_matches_type(UpdateResult, response.result, path=["response"])

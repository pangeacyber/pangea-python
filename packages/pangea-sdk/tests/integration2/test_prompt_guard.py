from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator

import pytest

from pangea import PangeaConfig
from pangea.asyncio.services.prompt_guard import PromptGuardAsync
from pangea.services import PromptGuard
from pangea.services.prompt_guard import GuardResult, Message

from ..utils import assert_matches_type

base_url = os.environ.get("TEST_API_BASE_URL", "http://127.0.0.1:4010")


@pytest.fixture(scope="session")
def client(request: pytest.FixtureRequest) -> Iterator[PromptGuard]:
    yield PromptGuard(token="my_api_token", config=PangeaConfig(base_url_template=base_url))


@pytest.fixture(scope="session")
async def async_client(request: pytest.FixtureRequest) -> AsyncIterator[PromptGuardAsync]:
    async with PromptGuardAsync(token="my_api_token", config=PangeaConfig(base_url_template=base_url)) as client:
        yield client


class TestPromptGuard:
    def test_guard(self, client: PromptGuard) -> None:
        response = client.guard([Message(role="user", content="hello world")], analyzers=["PA0000"], classify=True)
        assert response.status == "Success"
        assert response.result
        assert_matches_type(GuardResult, response.result, path=["response"])


class TestPromptGuardAsync:
    async def test_guard(self, async_client: PromptGuardAsync) -> None:
        response = await async_client.guard(
            [Message(role="user", content="hello world")], analyzers=["PA0000"], classify=True
        )
        assert response.status == "Success"
        assert response.result
        assert_matches_type(GuardResult, response.result, path=["response"])

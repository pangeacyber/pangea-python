from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator

import pytest

from pangea import PangeaConfig
from pangea.asyncio.services.ai_guard import AIGuardAsync
from pangea.services import AIGuard
from pangea.services.ai_guard import LogFields, Message, TextGuardResult

from ..utils import assert_matches_type

base_url = os.environ.get("TEST_API_BASE_URL", "http://127.0.0.1:4010")


@pytest.fixture(scope="session")
def client(request: pytest.FixtureRequest) -> Iterator[AIGuard]:
    yield AIGuard(token="my_api_token", config=PangeaConfig(base_url_template=base_url))


@pytest.fixture(scope="session")
async def async_client(request: pytest.FixtureRequest) -> AsyncIterator[AIGuardAsync]:
    yield AIGuardAsync(token="my_api_token", config=PangeaConfig(base_url_template=base_url))


class TestAIGuard:
    def test_text_guard(self, client: AIGuard) -> None:
        response = client.guard_text("hello world", recipe="my_recipe", debug=True)
        assert response.status == "Success"
        assert response.result
        assert_matches_type(TextGuardResult, response.result, path=["response"])

    def test_text_guard_messages(self, client: AIGuard) -> None:
        response = client.guard_text(
            messages=[Message(role="user", content="hello world")],
            debug=False,
            log_fields=LogFields(source="Acme Wizard"),
        )
        assert response.status == "Success"
        assert response.result
        assert_matches_type(TextGuardResult, response.result, path=["response"])


class TestAIGuardAsync:
    async def test_text_guard(self, async_client: AIGuardAsync) -> None:
        response = await async_client.guard_text("hello world", recipe="my_recipe", debug=True)
        assert response.status == "Success"
        assert response.result
        assert_matches_type(TextGuardResult, response.result, path=["response"])

    async def test_text_guard_messages(self, async_client: AIGuardAsync) -> None:
        response = await async_client.guard_text(
            messages=[Message(role="user", content="hello world")],
            debug=False,
            log_fields=LogFields(source="Acme Wizard"),
        )
        assert response.status == "Success"
        assert response.result
        assert_matches_type(TextGuardResult, response.result, path=["response"])

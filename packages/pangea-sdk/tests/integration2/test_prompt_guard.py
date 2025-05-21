from __future__ import annotations

import datetime
import os
from collections.abc import AsyncIterator, Iterator

import pytest

from pangea import PangeaConfig
from pangea.asyncio.services.prompt_guard import PromptGuardAsync
from pangea.response import PangeaResponseResult
from pangea.services import PromptGuard
from pangea.services.prompt_guard import ServiceConfigFilter, ServiceConfigsPage

from ..utils import assert_matches_type

base_url = os.environ.get("TEST_API_BASE_URL", "http://127.0.0.1:4010")


@pytest.fixture(scope="session")
def client(request: pytest.FixtureRequest) -> Iterator[PromptGuard]:
    yield PromptGuard(token="my_api_token", config=PangeaConfig(base_url_template=base_url))


@pytest.fixture(scope="session")
async def async_client(request: pytest.FixtureRequest) -> AsyncIterator[PromptGuardAsync]:
    yield PromptGuardAsync(token="my_api_token", config=PangeaConfig(base_url_template=base_url))


class TestPromptGuard:
    def test_get_service_config(self, client: PromptGuard) -> None:
        response = client.get_service_config(id="my_config_id")
        assert response.status == "Success"
        assert response.result
        assert_matches_type(PangeaResponseResult, response.result, path=["response"])

    def test_create_service_config(self, client: PromptGuard) -> None:
        response = client.create_service_config()
        assert response.status == "Success"
        assert response.result
        assert_matches_type(PangeaResponseResult, response.result, path=["response"])

    def test_update_service_config(self, client: PromptGuard) -> None:
        response = client.update_service_config()
        assert response.status == "Success"
        assert response.result
        assert_matches_type(PangeaResponseResult, response.result, path=["response"])

    def test_delete_service_config(self, client: PromptGuard) -> None:
        response = client.delete_service_config(id="my_config_id")
        assert response.status == "Success"
        assert response.result
        assert_matches_type(PangeaResponseResult, response.result, path=["response"])

    def test_list_service_configs(self, client: PromptGuard) -> None:
        response = client.list_service_configs(
            filter=ServiceConfigFilter(
                id="my_config_id",
                id__contains=["my", "config", "id"],
                created_at=datetime.datetime.now(),
            )
        )
        assert response.status == "Success"
        assert response.result
        assert_matches_type(ServiceConfigsPage, response.result, path=["response"])
        assert response.result.count is not None
        assert response.result.items is not None


class TestPromptGuardAsync:
    async def test_get_service_config(self, async_client: PromptGuardAsync) -> None:
        response = await async_client.get_service_config(id="my_config_id")
        assert response.status == "Success"
        assert response.result
        assert_matches_type(PangeaResponseResult, response.result, path=["response"])

    async def test_create_service_config(self, async_client: PromptGuardAsync) -> None:
        response = await async_client.create_service_config()
        assert response.status == "Success"
        assert response.result
        assert_matches_type(PangeaResponseResult, response.result, path=["response"])

    async def test_update_service_config(self, async_client: PromptGuardAsync) -> None:
        response = await async_client.update_service_config()
        assert response.status == "Success"
        assert response.result
        assert_matches_type(PangeaResponseResult, response.result, path=["response"])

    async def test_delete_service_config(self, async_client: PromptGuardAsync) -> None:
        response = await async_client.delete_service_config(id="my_config_id")
        assert response.status == "Success"
        assert response.result
        assert_matches_type(PangeaResponseResult, response.result, path=["response"])

    async def test_list_service_configs(self, async_client: PromptGuardAsync) -> None:
        response = await async_client.list_service_configs(
            filter=ServiceConfigFilter(
                id="my_config_id",
                id__contains=["my", "config", "id"],
                created_at=datetime.datetime.now(),
            )
        )
        assert response.status == "Success"
        assert response.result
        assert_matches_type(ServiceConfigsPage, response.result, path=["response"])
        assert response.result.count is not None
        assert response.result.items is not None

from __future__ import annotations

import datetime
import os
from collections.abc import AsyncIterator, Iterator

import pytest
from pydantic import AnyUrl

from pangea import PangeaConfig
from pangea.asyncio.services.ai_guard import AIGuardAsync
from pangea.services import AIGuard
from pangea.services.ai_guard import (
    ImageContent,
    LogFields,
    Message,
    MultimodalMessage,
    ServiceConfig,
    ServiceConfigFilter,
    ServiceConfigsPage,
    TextContent,
    TextGuardResult,
)

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

    def test_guard(self, client: AIGuard) -> None:
        response = client.guard(
            messages=[
                MultimodalMessage(
                    role="user",
                    content=[
                        TextContent(type="text", text="hello world"),
                        ImageContent(type="image", image_src=AnyUrl("https://example.org/favicon.ico")),
                        ImageContent(type="image", image_src=AnyUrl("data:image/jpeg;base64,000000")),
                    ],
                ),
            ],
            recipe="foobar",
            debug=True,
            app_name="foobar",
            context={"foo": "bar", "baz": 123},
        )
        assert response.status == "Success"
        assert response.result
        assert_matches_type(TextGuardResult, response.result, path=["response"])

    def test_get_service_config(self, client: AIGuard) -> None:
        response = client.get_service_config("my_config_id")
        assert response.status == "Success"
        assert response.result
        assert_matches_type(ServiceConfig, response.result, path=["response"])

    def test_create_service_config(self, client: AIGuard) -> None:
        response = client.create_service_config("my_config", recipes={})
        assert response.status == "Success"
        assert response.result
        assert_matches_type(ServiceConfig, response.result, path=["response"])

    def test_update_service_config(self, client: AIGuard) -> None:
        response = client.update_service_config(id="my_config_id", name="my_config", recipes={})
        assert response.status == "Success"
        assert response.result
        assert_matches_type(ServiceConfig, response.result, path=["response"])

    def test_delete_service_config(self, client: AIGuard) -> None:
        response = client.delete_service_config(id="my_config_id")
        assert response.status == "Success"
        assert response.result
        assert_matches_type(ServiceConfig, response.result, path=["response"])

    def test_list_service_configs(self, client: AIGuard) -> None:
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

    async def test_guard(self, async_client: AIGuardAsync) -> None:
        response = await async_client.guard(
            messages=[
                MultimodalMessage(
                    role="user",
                    content=[
                        TextContent(type="text", text="hello world"),
                        ImageContent(type="image", image_src=AnyUrl("https://example.org/favicon.ico")),
                        ImageContent(type="image", image_src=AnyUrl("data:image/jpeg;base64,000000")),
                    ],
                ),
            ],
            recipe="foobar",
            debug=True,
            app_name="foobar",
            context={"foo": "bar", "baz": 123},
        )
        assert response.status == "Success"
        assert response.result
        assert_matches_type(TextGuardResult, response.result, path=["response"])

    async def test_get_service_config(self, async_client: AIGuardAsync) -> None:
        response = await async_client.get_service_config("my_config_id")
        assert response.status == "Success"
        assert response.result
        assert_matches_type(ServiceConfig, response.result, path=["response"])

    async def test_create_service_config(self, async_client: AIGuardAsync) -> None:
        response = await async_client.create_service_config("my_config", recipes={})
        assert response.status == "Success"
        assert response.result
        assert_matches_type(ServiceConfig, response.result, path=["response"])

    async def test_update_service_config(self, async_client: AIGuardAsync) -> None:
        response = await async_client.update_service_config(id="my_config_id", name="my_config", recipes={})
        assert response.status == "Success"
        assert response.result
        assert_matches_type(ServiceConfig, response.result, path=["response"])

    async def test_delete_service_config(self, async_client: AIGuardAsync) -> None:
        response = await async_client.delete_service_config(id="my_config_id")
        assert response.status == "Success"
        assert response.result
        assert_matches_type(ServiceConfig, response.result, path=["response"])

    async def test_list_service_configs(self, async_client: AIGuardAsync) -> None:
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

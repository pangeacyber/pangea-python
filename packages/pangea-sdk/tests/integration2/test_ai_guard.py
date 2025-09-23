from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator

import pytest

from pangea import PangeaConfig
from pangea.asyncio.services.ai_guard import AIGuardAsync
from pangea.services import AIGuard
from pangea.services.ai_guard import (
    ExtraInfo,
    GuardResult,
    ImageDetectionItems,
    LogFields,
    Message,
    Overrides,
    TextGuardResult,
    get_relevant_content,
)

from ..utils import assert_matches_type

base_url = os.environ.get("TEST_API_BASE_URL", "http://127.0.0.1:4010")


@pytest.fixture(scope="session")
def client(request: pytest.FixtureRequest) -> Iterator[AIGuard]:
    yield AIGuard(token="my_api_token", config=PangeaConfig(base_url_template=base_url))


@pytest.fixture(scope="session")
async def async_client(request: pytest.FixtureRequest) -> AsyncIterator[AIGuardAsync]:
    async with AIGuardAsync(token="my_api_token", config=PangeaConfig(base_url_template=base_url)) as client:
        yield client


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
            input={"messages": [{"role": "user", "content": "hello world"}]},
            recipe="foobar",
            debug=True,
            app_id="foobar",
            extra_info=ExtraInfo(app_name="my app", foo="bar", baz="123"),
            overrides=Overrides(
                image=ImageDetectionItems(
                    disabled=False,
                    action="block",
                    topics=["test"],
                    threshold=0.5,
                ),
            ),
        )
        assert response.status == "Success"
        assert response.result
        assert_matches_type(GuardResult, response.result, path=["response"])


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
            input={"messages": [{"role": "user", "content": "hello world"}]},
            recipe="foobar",
            debug=True,
            app_id="foobar",
            extra_info=ExtraInfo(app_name="my app", foo="bar", baz="123"),
            overrides=Overrides(
                image=ImageDetectionItems(
                    disabled=False,
                    action="block",
                    topics=["test"],
                    threshold=0.5,
                ),
            ),
        )
        assert response.status == "Success"
        assert response.result
        assert_matches_type(GuardResult, response.result, path=["response"])


def test_get_relevant_content_empty() -> None:
    assert get_relevant_content([]) == ([], [])


def test_get_relevant_content_keeps_system() -> None:
    messages = [
        Message(
            role="system",
            content="You are a helpful assistant. Here are the tools: Tool1(calc), Tool2(site), Tool3(reverse)",
        ),
        Message(role="user", content="What is the sum of response times of example.com and example.org?"),
        Message(role="context", content="example.com and example.org are websites."),
    ]
    assert get_relevant_content(messages) == (
        [
            Message(
                role="system",
                content="You are a helpful assistant. Here are the tools: Tool1(calc), Tool2(site), Tool3(reverse)",
            ),
            Message(role="user", content="What is the sum of response times of example.com and example.org?"),
            Message(role="context", content="example.com and example.org are websites."),
        ],
        [0, 1, 2],
    )


def test_get_relevant_content_last_assistant() -> None:
    messages = [
        Message(
            role="system",
            content="You are a helpful assistant. Here are the tools: Tool1(calc), Tool2(site), Tool3(reverse)",
        ),
        Message(role="user", content="What is the sum of response times of example.com and example.org?"),
        Message(role="context", content="example.com and example.org are websites."),
        Message(role="assistant", content="Call Tool2(example.org)."),
    ]
    assert get_relevant_content(messages) == (
        [
            Message(
                role="system",
                content="You are a helpful assistant. Here are the tools: Tool1(calc), Tool2(site), Tool3(reverse)",
            ),
            Message(role="assistant", content="Call Tool2(example.org)."),
        ],
        [0, 3],
    )


def test_get_relevant_content_after_assistant() -> None:
    messages = [
        Message(
            role="system",
            content="You are a helpful assistant. Here are the tools: Tool1(calc), Tool2(site), Tool3(reverse)",
        ),
        Message(role="user", content="What is the sum of response times of example.com and example.org?"),
        Message(role="context", content="example.com and example.org are websites."),
        Message(role="assistant", content="Call Tool2(example.org)."),
        Message(role="tool", content="example.org 2ms"),
        Message(role="context", content="some context about example.org"),
    ]
    assert get_relevant_content(messages) == (
        [
            Message(
                role="system",
                content="You are a helpful assistant. Here are the tools: Tool1(calc), Tool2(site), Tool3(reverse)",
            ),
            Message(role="tool", content="example.org 2ms"),
            Message(role="context", content="some context about example.org"),
        ],
        [0, 4, 5],
    )

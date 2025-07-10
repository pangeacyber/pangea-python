from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator

import pytest

from pangea import PangeaConfig
from pangea.asyncio.services.authn import AuthNAsync
from pangea.services import AuthN
from pangea.services.authn.models import (
    ClientTokenCheckResult,
    SessionInvalidateResult,
    SessionListResults,
    UserProfileGetResult,
    UserProfileUpdateResult,
)

from ..utils import assert_matches_type

base_url = os.environ.get("TEST_API_BASE_URL", "http://127.0.0.1:4010")


@pytest.fixture(scope="session")
def client(request: pytest.FixtureRequest) -> Iterator[AuthN]:
    yield AuthN(token="my_api_token", config=PangeaConfig(base_url_template=base_url))


@pytest.fixture(scope="session")
async def async_client(request: pytest.FixtureRequest) -> AsyncIterator[AuthNAsync]:
    yield AuthNAsync(token="my_api_token", config=PangeaConfig(base_url_template=base_url))


class TestAuthN:
    def test_client_token_check(self, client: AuthN) -> None:
        response = client.client.token_endpoints.check(token="ptu_wuk7tvtpswyjtlsx52b7yyi2l7zotv4a")
        assert response.status == "Success"
        assert response.result
        assert_matches_type(ClientTokenCheckResult, response.result, path=["response"])

    def test_session_invalidate(self, client: AuthN) -> None:
        response = client.session.invalidate("pmt_jn4j24cg2ijbsgoc26xsase5an3ybtfk")
        assert response.status == "Success"
        assert response.result
        assert_matches_type(SessionInvalidateResult, response.result, path=["response"])

    def test_session_list(self, client: AuthN) -> None:
        response = client.session.list()
        assert response.status == "Success"
        assert response.result
        assert_matches_type(SessionListResults, response.result, path=["response"])

    def test_user_profile_get(self, client: AuthN) -> None:
        response = client.user.profile.get(email="foo@example.org")
        assert response.status == "Success"
        assert response.result
        assert_matches_type(UserProfileGetResult, response.result, path=["response"])

    def test_user_profile_update(self, client: AuthN) -> None:
        response = client.user.profile.update({"first_name": "Alice"})
        assert response.status == "Success"
        assert response.result
        assert_matches_type(UserProfileUpdateResult, response.result, path=["response"])


class TestAuthNAsync:
    async def test_client_token_check(self, async_client: AuthNAsync) -> None:
        response = await async_client.client.token_endpoints.check(token="ptu_wuk7tvtpswyjtlsx52b7yyi2l7zotv4a")
        assert response.status == "Success"
        assert response.result
        assert_matches_type(ClientTokenCheckResult, response.result, path=["response"])

    async def test_session_invalidate(self, async_client: AuthNAsync) -> None:
        response = await async_client.session.invalidate("pmt_jn4j24cg2ijbsgoc26xsase5an3ybtfk")
        assert response.status == "Success"
        assert response.result
        assert_matches_type(SessionInvalidateResult, response.result, path=["response"])

    async def test_session_list(self, async_client: AuthNAsync) -> None:
        response = await async_client.session.list()
        assert response.status == "Success"
        assert response.result
        assert_matches_type(SessionListResults, response.result, path=["response"])

    async def test_user_profile_get(self, async_client: AuthNAsync) -> None:
        response = await async_client.user.profile.get(email="foo@example.org")
        assert response.status == "Success"
        assert response.result
        assert_matches_type(UserProfileGetResult, response.result, path=["response"])

    async def test_user_profile_update(self, async_client: AuthNAsync) -> None:
        response = await async_client.user.profile.update({"first_name": "Alice"})
        assert response.status == "Success"
        assert response.result
        assert_matches_type(UserProfileUpdateResult, response.result, path=["response"])

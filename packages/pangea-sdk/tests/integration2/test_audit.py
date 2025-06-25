from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator

import pytest

from pangea import PangeaConfig
from pangea.asyncio.services.audit import AuditAsync
from pangea.services import Audit
from pangea.services.audit.models import LogResult

from ..utils import assert_matches_type

base_url = os.environ.get("TEST_API_BASE_URL", "http://127.0.0.1:4010")


@pytest.fixture(scope="session")
def client(request: pytest.FixtureRequest) -> Iterator[Audit]:
    yield Audit(token="my_api_token", config=PangeaConfig(base_url_template=base_url))


@pytest.fixture(scope="session")
async def async_client(request: pytest.FixtureRequest) -> AsyncIterator[AuditAsync]:
    yield AuditAsync(token="my_api_token", config=PangeaConfig(base_url_template=base_url))


class TestAudit:
    @pytest.mark.skip(reason="assert_matches_type lacks support for enums")
    def test_log(self, client: Audit) -> None:
        response = client.log(message="hello world")
        assert response.status == "Success"
        assert response.result
        assert_matches_type(LogResult, response.result, path=["response"])


class TestAuditAsync:
    @pytest.mark.skip(reason="assert_matches_type lacks support for enums")
    async def test_log(self, async_client: AuditAsync) -> None:
        response = await async_client.log(message="hello world")
        assert response.status == "Success"
        assert response.result
        assert_matches_type(LogResult, response.result, path=["response"])

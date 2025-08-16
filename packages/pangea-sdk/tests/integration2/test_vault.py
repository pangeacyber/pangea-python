from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator

import pytest

from pangea import PangeaConfig
from pangea.asyncio.services import VaultAsync
from pangea.services import Vault
from pangea.services.vault.models.common import FolderCreateResult

from ..utils import assert_matches_type

base_url = os.environ.get("TEST_API_BASE_URL", "http://127.0.0.1:4010")


@pytest.fixture(scope="session")
def client(request: pytest.FixtureRequest) -> Iterator[Vault]:
    yield Vault(token="my_api_token", config=PangeaConfig(base_url_template=base_url))


@pytest.fixture(scope="session")
async def async_client(request: pytest.FixtureRequest) -> AsyncIterator[VaultAsync]:
    async with VaultAsync(token="my_api_token", config=PangeaConfig(base_url_template=base_url)) as client:
        yield client


class TestVault:
    def test_folder_create(self, client: Vault) -> None:
        response = client.folder_create("name", "folder", metadata={"key": "value"})
        assert response.status == "Success"
        assert response.result
        assert_matches_type(FolderCreateResult, response.result, path=["response"])


class TestVaultAsync:
    async def test_folder_create(self, async_client: VaultAsync) -> None:
        response = await async_client.folder_create("name", "folder", metadata={"key": "value"})
        assert response.status == "Success"
        assert response.result
        assert_matches_type(FolderCreateResult, response.result, path=["response"])

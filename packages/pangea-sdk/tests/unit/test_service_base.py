from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import pytest

from pangea.asyncio.services.base import ServiceBaseAsync
from pangea.services.base import PangeaConfig, ServiceBase


@pytest.fixture(scope="session")
def base(request: pytest.FixtureRequest) -> Iterator[ServiceBase]:
    yield ServiceBase("my_token", PangeaConfig(domain="my_domain"))


@pytest.fixture(scope="session")
async def async_base(request: pytest.FixtureRequest) -> AsyncIterator[ServiceBaseAsync]:
    yield ServiceBaseAsync("my_token", PangeaConfig(domain="my_domain"))


class TestServiceBase:
    def test_service_base(self, base: ServiceBase) -> None:
        assert base.token == "my_token"

        base.token = "newtoken"
        assert base.token == "newtoken"

    def test_service_base_no_token(self) -> None:
        with pytest.raises(Exception):
            ServiceBase(None, PangeaConfig(domain="domain"))  # type: ignore[arg-type]

    def test_extra_headers(self, base: ServiceBase) -> None:
        base.request.set_extra_headers({"Host": "foobar"})
        assert "Host" in base.request._headers()
        assert base.request._headers()["Host"] == "foobar"


class TestServiceBaseAsync:
    def test_service_base(self, async_base: ServiceBaseAsync) -> None:
        assert async_base.token == "my_token"

        async_base.token = "newtoken"
        assert async_base.token == "newtoken"

    def test_service_base_no_token(self) -> None:
        with pytest.raises(Exception):
            ServiceBaseAsync(None, PangeaConfig(domain="domain"))  # type: ignore[arg-type]

    def test_extra_headers(self, async_base: ServiceBaseAsync) -> None:
        async_base.request.set_extra_headers({"Host": "foobar"})
        assert "Host" in async_base.request._headers()
        assert async_base.request._headers()["Host"] == "foobar"

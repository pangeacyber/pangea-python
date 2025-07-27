from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator

import pytest

from pangea import PangeaConfig
from pangea.asyncio.services import IpIntelAsync
from pangea.services import IpIntel
from pangea.services.intel import (
    IPDomainBulkResult,
    IPGeolocateBulkResult,
    IPProxyBulkResult,
    IPReputationBulkResult,
    IPVPNBulkResult,
)

from ..utils import assert_matches_type

base_url = os.environ.get("TEST_API_BASE_URL", "http://127.0.0.1:4010")


@pytest.fixture(scope="session")
def client(request: pytest.FixtureRequest) -> Iterator[IpIntel]:
    yield IpIntel(token="my_api_token", config=PangeaConfig(base_url_template=base_url))


@pytest.fixture(scope="session")
async def async_client(request: pytest.FixtureRequest) -> AsyncIterator[IpIntelAsync]:
    async with IpIntelAsync(token="my_api_token", config=PangeaConfig(base_url_template=base_url)) as client:
        yield client


class TestIpIntel:
    def test_geolocate_bulk(self, client: IpIntel) -> None:
        response = client.geolocate_bulk(ips=("1.1.1.1", "1.0.0.1"), verbose=True, raw=True, provider="digitalelement")
        assert response.status == "Success"
        assert response.result
        assert_matches_type(IPGeolocateBulkResult, response.result, path=["response"])

    def test_get_domain_bulk(self, client: IpIntel) -> None:
        response = client.get_domain_bulk(ips=("1.1.1.1", "1.0.0.1"), verbose=True, raw=True, provider="digitalelement")
        assert response.status == "Success"
        assert response.result
        assert_matches_type(IPDomainBulkResult, response.result, path=["response"])

    def test_is_proxy_bulk(self, client: IpIntel) -> None:
        response = client.is_proxy_bulk(ips=("1.1.1.1", "1.0.0.1"), verbose=True, raw=True, provider="digitalelement")
        assert response.status == "Success"
        assert response.result
        assert_matches_type(IPProxyBulkResult, response.result, path=["response"])

    def test_is_vpn_bulk(self, client: IpIntel) -> None:
        response = client.is_vpn_bulk(ips=("1.1.1.1", "1.0.0.1"), verbose=True, raw=True, provider="digitalelement")
        assert response.status == "Success"
        assert response.result
        assert_matches_type(IPVPNBulkResult, response.result, path=["response"])

    def test_reputation_bulk(self, client: IpIntel) -> None:
        response = client.reputation_bulk(ips=("1.1.1.1", "1.0.0.1"), verbose=True, raw=True, provider="crowdstrike")
        assert response.status == "Success"
        assert response.result
        assert_matches_type(IPReputationBulkResult, response.result, path=["response"])


class TestIpIntelAsync:
    async def test_geolocate_bulk(self, async_client: IpIntelAsync) -> None:
        response = await async_client.geolocate_bulk(
            ips=("1.1.1.1", "1.0.0.1"), verbose=True, raw=True, provider="digitalenvoy"
        )
        assert response.status == "Success"
        assert response.result
        assert_matches_type(IPGeolocateBulkResult, response.result, path=["response"])

    async def test_get_domain_bulk(self, async_client: IpIntelAsync) -> None:
        response = await async_client.get_domain_bulk(
            ips=("1.1.1.1", "1.0.0.1"), verbose=True, raw=True, provider="digitalenvoy"
        )
        assert response.status == "Success"
        assert response.result
        assert_matches_type(IPDomainBulkResult, response.result, path=["response"])

    async def test_is_proxy_bulk(self, async_client: IpIntelAsync) -> None:
        response = await async_client.is_proxy_bulk(
            ips=("1.1.1.1", "1.0.0.1"), verbose=True, raw=True, provider="digitalenvoy"
        )
        assert response.status == "Success"
        assert response.result
        assert_matches_type(IPProxyBulkResult, response.result, path=["response"])

    async def test_is_vpn_bulk(self, async_client: IpIntelAsync) -> None:
        response = await async_client.is_vpn_bulk(
            ips=("1.1.1.1", "1.0.0.1"), verbose=True, raw=True, provider="digitalenvoy"
        )
        assert response.status == "Success"
        assert response.result
        assert_matches_type(IPVPNBulkResult, response.result, path=["response"])

    async def test_reputation_bulk(self, async_client: IpIntelAsync) -> None:
        response = await async_client.reputation_bulk(
            ips=("1.1.1.1", "1.0.0.1"), verbose=True, raw=True, provider="cymru"
        )
        assert response.status == "Success"
        assert response.result
        assert_matches_type(IPReputationBulkResult, response.result, path=["response"])

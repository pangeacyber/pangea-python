# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import hashlib
from typing import List, Optional

import pangea.services.intel as m
from pangea.asyncio.services.base import ServiceBaseAsync
from pangea.response import PangeaResponse
from pangea.utils import hash_256_filepath


class FileIntelAsync(ServiceBaseAsync):
    """File Intel service client

    Provides methods to interact with [Pangea File Intel Service](https://pangea.cloud/docs/api/file-intel)

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import FileIntel

        PANGEA_TOKEN = os.getenv("PANGEA_INTEL_TOKEN")

        file_intel_config = PangeaConfig(domain="aws.us.pangea.cloud")

        # Setup Pangea File Intel service
        file_intel = FileIntel(token=PANGEA_TOKEN, config=file_intel_config)
    """

    service_name = "file-intel"

    async def hash_reputation(
        self,
        hash: str,
        hash_type: str,
        provider: Optional[str] = None,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
    ) -> PangeaResponse[m.FileReputationResult]:
        """
        Reputation check

        Retrieve hash-based file reputation from a provider, including an optional detailed report.

        Args:
            hash (str): The hash of the file to be looked up
            hash_type (str): One of "sha256", "sha", "md5"
            provider (str, optional): Use reputation data from these providers: "reversinglabs" or "crowdstrike"
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/file-intel).

        Examples:
            response = await file_intel.hashReputation(hash="142b638c6a60b60c7f9928da4fb85a5a8e1422a9ffdc9ee49e17e56ccca9cf6e", hash_type="sha256", provider="reversinglabs")

        """
        input = m.FileReputationRequest(hash=hash, hash_type=hash_type, verbose=verbose, raw=raw, provider=provider)
        return await self.request.post(
            "v1/reputation", m.FileReputationResult, data=input.model_dump(exclude_none=True)
        )

    async def hash_reputation_bulk(
        self,
        hashes: List[str],
        hash_type: str,
        provider: Optional[str] = None,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
    ) -> PangeaResponse[m.FileReputationBulkResult]:
        """
        Reputation check

        Retrieve hash-based file reputation from a provider, including an optional detailed report.

        Args:
            hashes (List[str]): The hash of each file to be looked up
            hash_type (str): One of "sha256", "sha", "md5"
            provider (str, optional): Use reputation data from these providers: "reversinglabs" or "crowdstrike"
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/file-intel).

        Examples:
            FIXME:

        """
        input = m.FileReputationBulkRequest(  # type: ignore[call-arg]
            hashes=hashes, hash_type=hash_type, verbose=verbose, raw=raw, provider=provider
        )
        return await self.request.post(
            "v2/reputation", m.FileReputationBulkResult, data=input.model_dump(exclude_none=True)
        )

    async def filepath_reputation(
        self,
        filepath: str,
        provider: Optional[str] = None,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
    ) -> PangeaResponse[m.FileReputationResult]:
        """
        Reputation, from filepath

        Retrieve hash-based file reputation from a provider, including an optional detailed report.
        This function take care of calculate filepath hash and make the request to service

        OperationId: file_intel_post_v1_reputation

        Args:
            filepath (str): The path to the file to be looked up
            provider (str, optional): Use reputation data from these providers: "reversinglabs" or "crowdstrike"
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/file-intel).

        Examples:
            response = await file_intel.filepathReputation(
                filepath="./myfile.exe",
                provider="reversinglabs",
            )
        """

        data = open(filepath, "rb")
        hash = hashlib.sha256(data.read()).hexdigest()

        input = m.FileReputationRequest(hash=hash, hash_type="sha256", verbose=verbose, raw=raw, provider=provider)
        return await self.request.post(
            "v1/reputation", m.FileReputationResult, data=input.model_dump(exclude_none=True)
        )

    async def filepath_reputation_bulk(
        self,
        filepaths: List[str],
        provider: Optional[str] = None,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
    ) -> PangeaResponse[m.FileReputationBulkResult]:
        """
        Reputation, from filepath

        Retrieve hash-based file reputation from a provider, including an optional detailed report.
        This function take care of calculate filepath hash and make the request to service

        OperationId: file_intel_post_v1_reputation

        Args:
            filepaths (List[str]): The path list to the files to be looked up
            provider (str, optional): Use reputation data from these providers: "reversinglabs" or "crowdstrike"
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/file-intel).

        Examples:
            FIXME:
        """
        hashes = []
        for filepath in filepaths:
            hash = hash_256_filepath(filepath)
            hashes.append(hash)

        return await self.hash_reputation_bulk(
            hashes=hashes, hash_type="sha256", verbose=verbose, raw=raw, provider=provider
        )


class DomainIntelAsync(ServiceBaseAsync):
    """Domain Intel service client

    Provides methods to interact with [Pangea Domain Intel Service](https://pangea.cloud/docs/api/domain-intel)

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import DomainIntel

        PANGEA_TOKEN = os.getenv("PANGEA_INTEL_TOKEN")

        domain_intel_config = PangeaConfig(domain="aws.us.pangea.cloud")

        # Setup Pangea Domain Intel service
        domain_intel = DomainIntel(token=PANGEA_TOKEN, config=domain_intel_config)
    """

    service_name = "domain-intel"

    async def reputation(
        self, domain: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[m.DomainReputationResult]:
        """
        Reputation

        Retrieve reputation for a domain from a provider, including an optional detailed report.

        OperationId: domain_intel_post_v1_reputation

        Args:
            domain (str): The domain to be looked up
            provider (str, optional): Use reputation data from these providers: "domaintools" or "crowdstrike"
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/domain-intel).

        Examples:
            response = await domain_intel.reputation(
                domain="737updatesboeing.com",
                provider="domaintools",
            )
        """
        input = m.DomainReputationRequest(domain=domain, verbose=verbose, provider=provider, raw=raw)
        return await self.request.post(
            "v1/reputation", m.DomainReputationResult, data=input.model_dump(exclude_none=True)
        )

    async def reputation_bulk(
        self,
        domains: List[str],
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
        provider: Optional[str] = None,
    ) -> PangeaResponse[m.DomainReputationBulkResult]:
        """
        Reputation

        Retrieve reputation for a domain from a provider, including an optional detailed report.

        OperationId: FIXME:

        Args:
            domains (List[str]): The domain list to be looked up
            provider (str, optional): Use reputation data from these providers: "domaintools" or "crowdstrike"
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/domain-intel).

        Examples:
            FIXME:
        """
        input = m.DomainReputationBulkRequest(domains=domains, verbose=verbose, provider=provider, raw=raw)
        return await self.request.post(
            "v2/reputation", m.DomainReputationBulkResult, data=input.model_dump(exclude_none=True)
        )

    async def who_is(
        self, domain: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[m.DomainWhoIsResult]:
        """
        WhoIs

        Retrieve who is for a domain from a provider, including an optional detailed report.

        OperationId: domain_intel_post_v1_whois

        Args:
            domain (str): The domain to query.
            provider (str, optional): Use whois data from this provider "whoisxml"
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/domain-intel).

        Examples:
            response = await domain_intel.who_is(
                domain="google.com",
                provider="whoisxml",
            )
        """
        input = m.DomainWhoIsRequest(domain=domain, verbose=verbose, provider=provider, raw=raw)  # type: ignore[call-arg]
        return await self.request.post("v1/whois", m.DomainWhoIsResult, data=input.model_dump(exclude_none=True))


class IpIntelAsync(ServiceBaseAsync):
    """IP Intel service client

    Provides methods to interact with [Pangea IP Intel Service](/docs/api/ip-intel)

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import IpIntel

        PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")

        ip_intel_config = PangeaConfig(domain="pangea.cloud")

        # Setup Pangea IP Intel service
        ip_intel = IpIntel(token=PANGEA_TOKEN, config=ip_intel_config)
    """

    service_name = "ip-intel"

    async def reputation(
        self, ip: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[m.IPReputationResult]:
        """
        Reputation

        Retrieve a reputation score for an IP address from a provider, including an optional detailed report.

        OperationId: ip_intel_post_v1_reputation

        Args:
            ip (str): The IP to be looked up
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider
            provider (str, optional): Use reputation data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/ip-intel)

        Examples:
            response = await ip_intel.reputation(
                ip="93.231.182.110",
                provider="crowdstrike",
            )
        """
        input = m.IPReputationRequest(ip=ip, verbose=verbose, raw=raw, provider=provider)
        return await self.request.post("v1/reputation", m.IPReputationResult, data=input.model_dump(exclude_none=True))

    async def reputation_bulk(
        self, ips: List[str], verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[m.IPReputationBulkResult]:
        """
        Reputation

        Retrieve a reputation score for an IP address from a provider, including an optional detailed report.

        OperationId: FIXME:

        Args:
            ips (List[str]): The IP list to be looked up
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider
            provider (str, optional): Use reputation data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/ip-intel)

        Examples:
            FIXME:
        """
        input = m.IPReputationBulkRequest(ips=ips, verbose=verbose, raw=raw, provider=provider)
        return await self.request.post(
            "v2/reputation", m.IPReputationBulkResult, data=input.model_dump(exclude_none=True)
        )

    async def geolocate(
        self, ip: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[m.IPGeolocateResult]:
        """
        Geolocate

        Retrieve information about the location of an IP address.

        OperationId: ip_intel_post_v1_geolocate

        Args:
            ips (List[str]): IP address' list to be geolocated
            provider (str, optional): Use geolocation data from this provider ("digitalelement"). Default provider defined by the configuration.
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the IP information is in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/ip-intel)

        Examples:
            response = await ip_intel.geolocate(
                ip="93.231.182.110",
                provider="digitalelement",
            )
        """
        input = m.IPGeolocateRequest(ip=ip, verbose=verbose, raw=raw, provider=provider)
        return await self.request.post("v1/geolocate", m.IPGeolocateResult, data=input.model_dump(exclude_none=True))

    async def geolocate_bulk(
        self, ips: List[str], verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[m.IPGeolocateBulkResult]:
        """
        Geolocate

        Retrieve information about the location of an IP address.

        OperationId: FIXME:

        Args:
            ips (List[str]): IP addresses list to be geolocated
            provider (str, optional): Use geolocation data from this provider ("digitalelement"). Default provider defined by the configuration.
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the IP information is in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/ip-intel)

        Examples:
            FIXME:
        """
        input = m.IPGeolocateBulkRequest(ips=ips, verbose=verbose, raw=raw, provider=provider)
        return await self.request.post(
            "v2/geolocate", m.IPGeolocateBulkResult, data=input.model_dump(exclude_none=True)
        )

    async def get_domain(
        self, ip: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[m.IPDomainResult]:
        """
        Domain

        Retrieve the domain name associated with an IP address.

        OperationId: ip_intel_post_v1_domain

        Args:
            ip (str): The IP to be looked up
            provider (str, optional): Use geolocation data from this provider ("digitalelement"). Default provider defined by the configuration.
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the IP information is in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/ip-intel)

        Examples:
            response = await ip_intel.get_domain(
                ip="93.231.182.110",
                provider="digitalelement",
            )
        """
        input = m.IPDomainRequest(ip=ip, verbose=verbose, raw=raw, provider=provider)
        return await self.request.post("v1/domain", m.IPDomainResult, data=input.model_dump(exclude_none=True))

    async def get_domain_bulk(
        self, ips: List[str], verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[m.IPDomainBulkResult]:
        """
        Domain

        Retrieve the domain name associated with an IP address.

        OperationId: FIXME:

        Args:
            ips (List[str]): The IP to be looked up
            provider (str, optional): Use geolocation data from this provider ("digitalelement"). Default provider defined by the configuration.
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the IP information is in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/ip-intel)

        Examples:
            FIXME:
        """
        input = m.IPDomainBulkRequest(ips=ips, verbose=verbose, raw=raw, provider=provider)
        return await self.request.post("v2/domain", m.IPDomainBulkResult, data=input.model_dump(exclude_none=True))

    async def is_vpn(
        self, ip: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[m.IPVPNResult]:
        """
        VPN

        Determine if an IP address is provided by a VPN service.

        OperationId: ip_intel_post_v1_vpn

        Args:
            ip (str): The IP to be looked up
            provider (str, optional): Use geolocation data from this provider ("digitalelement"). Default provider defined by the configuration.
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the IP information is in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/ip-intel)

        Examples:
            response = await ip_intel.is_vpn(
                ip="93.231.182.110",
                provider="digitalelement",
            )
        """
        input = m.IPVPNRequest(ip=ip, verbose=verbose, raw=raw, provider=provider)
        return await self.request.post("v1/vpn", m.IPVPNResult, data=input.model_dump(exclude_none=True))

    async def is_vpn_bulk(
        self, ips: List[str], verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[m.IPVPNBulkResult]:
        """
        VPN

        Determine if an IP address is provided by a VPN service.

        OperationId: FIXME:

        Args:
            ips (List[str]): The IP's list to be looked up
            provider (str, optional): Use geolocation data from this provider ("digitalelement"). Default provider defined by the configuration.
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the IP information is in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/ip-intel)

        Examples:
            FIXME:
        """
        input = m.IPVPNBulkRequest(ips=ips, verbose=verbose, raw=raw, provider=provider)
        return await self.request.post("v2/vpn", m.IPVPNBulkResult, data=input.model_dump(exclude_none=True))

    async def is_proxy(
        self, ip: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[m.IPProxyResult]:
        """
        Proxy

        Determine if an IP address is provided by a proxy service.

        OperationId: ip_intel_post_v1_proxy

        Args:
            ip (str): The IP to be looked up
            provider (str, optional): Use geolocation data from this provider ("digitalelement"). Default provider defined by the configuration.
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the IP information is in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/ip-intel)

        Examples:
            response = await ip_intel.is_proxy(
                ip="93.231.182.110",
                provider="digitalelement",
            )
        """
        input = m.IPProxyRequest(ip=ip, verbose=verbose, raw=raw, provider=provider)
        return await self.request.post("v1/proxy", m.IPProxyResult, data=input.model_dump(exclude_none=True))

    async def is_proxy_bulk(
        self, ips: List[str], verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[m.IPProxyBulkResult]:
        """
        Proxy

        Determine if an IP address is provided by a proxy service.

        OperationId: FIXME:

        Args:
            ips (List[str]): The IP's list to be looked up
            provider (str, optional): Use geolocation data from this provider ("digitalelement"). Default provider defined by the configuration.
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the IP information is in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/ip-intel)

        Examples:
            FIXME:
        """
        input = m.IPProxyBulkRequest(ips=ips, verbose=verbose, raw=raw, provider=provider)
        return await self.request.post("v2/proxy", m.IPProxyBulkResult, data=input.model_dump(exclude_none=True))


class UrlIntelAsync(ServiceBaseAsync):
    """URL Intel service client.

    Provides methods to interact with [Pangea URL Intel Service](/docs/api/url-intel)

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import UrlIntel

        PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")

        url_intel_config = PangeaConfig(domain="pangea.cloud")

        # Setup Pangea URL Intel service
        url_intel = UrlIntel(token=PANGEA_TOKEN, config=url_intel_config)
    """

    service_name = "url-intel"

    async def reputation(
        self, url: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[m.URLReputationResult]:
        """
        Reputation

        Retrieve URL address reputation from a provider.

        OperationId: url_intel_post_v1_reputation

        Args:
            url (str): The URL to be looked up
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider
            provider (str, optional): Use reputation data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/url-intel)

        Examples:
            response = await url_intel.reputation(
                url="http://113.235.101.11:54384",
                provider="crowdstrike",
            )
        """

        input = m.URLReputationRequest(url=url, provider=provider, verbose=verbose, raw=raw)
        return await self.request.post("v1/reputation", m.URLReputationResult, data=input.model_dump(exclude_none=True))

    async def reputation_bulk(
        self,
        urls: List[str],
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
        provider: Optional[str] = None,
    ) -> PangeaResponse[m.URLReputationBulkResult]:
        """
        Reputation

        Retrieve URL address reputation from a provider.

        OperationId: FIXME:

        Args:
            urls (List[str]): The URL list to be looked up
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider
            provider (str, optional): Use reputation data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/url-intel)

        Examples:
            FIXME:
        """

        input = m.URLReputationBulkRequest(urls=urls, provider=provider, verbose=verbose, raw=raw)
        return await self.request.post(
            "v2/reputation", m.URLReputationBulkResult, data=input.model_dump(exclude_none=True)
        )


class UserIntelAsync(ServiceBaseAsync):
    """User Intel service client.

    Provides methods to interact with [Pangea User Intel Service](/docs/api/user-intel)

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import UserIntel

        PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")

        user_intel_config = PangeaConfig(domain="pangea.cloud")

        # Setup Pangea User Intel service
        user_intel = UserIntel(token=PANGEA_TOKEN, config=user_intel_config)
    """

    service_name = "user-intel"

    async def user_breached(
        self,
        email: Optional[str] = None,
        username: Optional[str] = None,
        ip: Optional[str] = None,
        phone_number: Optional[str] = None,
        start: Optional[str] = None,
        end: Optional[str] = None,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
        provider: Optional[str] = None,
        cursor: Optional[str] = None,
    ) -> PangeaResponse[m.UserBreachedResult]:
        """
        Look up breached users

        Find out if an email address, username, phone number, or IP address was exposed in a security breach.

        OperationId: user_intel_post_v1_user_breached

        Args:
            email (str): An email address to search for
            username (str): An username to search for
            ip (str): An ip to search for
            phone_number (str): A phone number to search for. minLength: 7, maxLength: 15.
            start (str): Earliest date for search
            end (str): Latest date for search
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider
            provider (str, optional): Use reputation data from this provider
            cursor (str, optional): A token given in the raw response from SpyCloud. Post this back to paginate results

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/url-intel)

        Examples:
            response = await user_intel.user_breached(
                phone_number="8005550123",
                provider="spycloud",
                verbose=True,
                raw=True,
            )
        """

        input = m.UserBreachedRequest(
            email=email,
            phone_number=phone_number,
            username=username,
            ip=ip,
            provider=provider,
            start=start,
            end=end,
            verbose=verbose,
            raw=raw,
            cursor=cursor,
        )
        return await self.request.post(
            "v1/user/breached", m.UserBreachedResult, data=input.model_dump(exclude_none=True)
        )

    async def user_breached_bulk(
        self,
        emails: Optional[List[str]] = None,
        usernames: Optional[List[str]] = None,
        ips: Optional[List[str]] = None,
        phone_numbers: Optional[List[str]] = None,
        domains: Optional[List[str]] = None,
        start: Optional[str] = None,
        end: Optional[str] = None,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
        provider: Optional[str] = None,
    ) -> PangeaResponse[m.UserBreachedBulkResult]:
        """
        Look up breached users

        Find out if an email address, username, phone number, or IP address was exposed in a security breach.

        OperationId: FIXME:

        Args:
            emails (List[str]): An email address' list to search for
            usernames (List[str]): An username's list to search for
            ips (List[str]): An ip's list to search for
            phone_numbers (List[str]): A phone number's list to search for. minLength: 7, maxLength: 15.
            domains (List[str]): Search for user under these domains.
            start (str): Earliest date for search
            end (str): Latest date for search
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider
            provider (str, optional): Use reputation data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/url-intel)

        Examples:
            FIXME:
        """

        input = m.UserBreachedBulkRequest(
            emails=emails,
            phone_numbers=phone_numbers,
            usernames=usernames,
            ips=ips,
            domains=domains,
            provider=provider,
            start=start,
            end=end,
            verbose=verbose,
            raw=raw,
        )
        return await self.request.post(
            "v2/user/breached", m.UserBreachedBulkResult, data=input.model_dump(exclude_none=True)
        )

    async def password_breached(
        self,
        hash_type: m.HashType,
        hash_prefix: str,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = True,
        provider: Optional[str] = None,
    ) -> PangeaResponse[m.UserPasswordBreachedResult]:
        """
        Look up breached passwords

        Find out if a password has been exposed in security breaches by providing a 5 character prefix of the password hash.

        OperationId: user_intel_post_v1_password_breached

        Args:
            hash_type (str): Hash type to be looked up
            hash_prefix (str): The prefix of the hash to be looked up.
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider
            provider (str, optional): Use reputation data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/url-intel)

        Examples:
            response = await user_intel.password_breached(
                hash_prefix="5baa6",
                hash_type=HashType.SHA256,
                provider="spycloud",
            )
        """

        input = m.UserPasswordBreachedRequest(
            hash_type=hash_type, hash_prefix=hash_prefix, provider=provider, verbose=verbose, raw=raw
        )
        return await self.request.post(
            "v1/password/breached", m.UserPasswordBreachedResult, data=input.model_dump(exclude_none=True)
        )

    async def password_breached_bulk(
        self,
        hash_type: m.HashType,
        hash_prefixes: List[str],
        verbose: Optional[bool] = None,
        raw: Optional[bool] = True,
        provider: Optional[str] = None,
    ) -> PangeaResponse[m.UserPasswordBreachedBulkResult]:
        """
        Look up breached passwords

        Find out if a password has been exposed in security breaches by providing a 5 character prefix of the password hash.

        OperationId: FIXME:

        Args:
            hash_type (str): Hash type to be looked up
            hash_prefixes (List[str]): The list of prefixes of the hash to be looked up.
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider
            provider (str, optional): Use reputation data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/url-intel)

        Examples:
            FIXME:
        """

        input = m.UserPasswordBreachedBulkRequest(
            hash_type=hash_type, hash_prefixes=hash_prefixes, provider=provider, verbose=verbose, raw=raw
        )
        return await self.request.post(
            "v2/password/breached", m.UserPasswordBreachedBulkResult, data=input.model_dump(exclude_none=True)
        )

    async def breach(
        self,
        breach_id: str,
        verbose: Optional[bool] = None,
        provider: Optional[str] = None,
        cursor: Optional[str] = None,
        start: Optional[str] = None,
        end: Optional[str] = None,
        severity: Optional[List[int]] = None,
    ) -> PangeaResponse[m.BreachResult]:
        """
        Look up information about a specific breach

        Given a provider specific breach ID, find details about the breach.

        OperationId: user_intel_post_v1_breach

        Args:
            breach_id (str, optional): The ID of a breach returned by a provider
            verbose (bool, optional): Echo the API parameters in the response
            provider (str, optional): Use reputation data from this provider
            cursor (str, optional): A token given in the raw response from SpyCloud. Post this back to paginate results
            start (str, optional): This parameter allows you to define the starting point for a date range query on the spycloud_publish_date field
            end (str, optional): This parameter allows you to define the ending point for a date range query on the spycloud_publish_date field
            severity (List[int], optional): Filter for records that match one of the given severities

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the breach details are in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/user-intel)

        Examples:
            response = await user_intel.breach(
                breach_id="66111",
            )
        """

        input = m.BreachRequest(
            breach_id=breach_id,
            provider=provider,
            verbose=verbose,
            cursor=cursor,
            start=start,
            end=end,
            severity=severity,
        )
        return await self.request.post("v1/breach", m.BreachResult, data=input.model_dump(exclude_none=True))

# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import hashlib
from typing import Optional

import pangea.services.intel as m
from pangea.exceptions import PangeaException
from pangea.response import PangeaResponse

from .base import ServiceBaseAsync


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
        return await self.request.post("v1/reputation", m.FileReputationResult, data=input.dict(exclude_none=True))

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
        return await self.request.post("v1/reputation", m.FileReputationResult, data=input.dict(exclude_none=True))


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
        return await self.request.post("v1/reputation", m.DomainReputationResult, data=input.dict(exclude_none=True))

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
        input = m.DomainWhoIsRequest(domain=domain, verbose=verbose, provider=provider, raw=raw)
        return await self.request.post("v1/whois", m.DomainWhoIsResult, data=input.dict(exclude_none=True))


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
            provider (str, optional): Use reputation data from this provider: "crowdstrike"

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
        input = m.IPRepurationRequest(ip=ip, verbose=verbose, raw=raw, provider=provider)
        return await self.request.post("v1/reputation", m.IPReputationResult, data=input.dict(exclude_none=True))

    async def geolocate(
        self, ip: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[m.IPGeolocateResult]:
        """
        Geolocate

        Retrieve information about the location of an IP address.

        OperationId: ip_intel_post_v1_geolocate

        Args:
            ip (str): IP address to be geolocated
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
        return await self.request.post("v1/geolocate", m.IPGeolocateResult, data=input.dict(exclude_none=True))

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
        return await self.request.post("v1/domain", m.IPDomainResult, data=input.dict(exclude_none=True))

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
        return await self.request.post("v1/vpn", m.IPVPNResult, data=input.dict(exclude_none=True))

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
        return await self.request.post("v1/proxy", m.IPProxyResult, data=input.dict(exclude_none=True))


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
            provider (str, optional): Use reputation data from this provider: "crowdstrike"

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
        return await self.request.post("v1/reputation", m.URLReputationResult, data=input.dict(exclude_none=True))


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
            provider (str, optional): Use reputation data from this provider: "crowdstrike"

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
        )
        return await self.request.post("v1/user/breached", m.UserBreachedResult, data=input.dict(exclude_none=True))

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
            provider (str, optional): Use reputation data from this provider: "crowdstrike"

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
            "v1/password/breached", m.UserPasswordBreachedResult, data=input.dict(exclude_none=True)
        )

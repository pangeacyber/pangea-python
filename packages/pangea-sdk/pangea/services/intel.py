# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from __future__ import annotations

import enum
import hashlib
from typing import Dict, List, Optional

from pangea.exceptions import PangeaException
from pangea.response import APIRequestModel, PangeaResponse, PangeaResponseResult
from pangea.services.base import ServiceBase
from pangea.utils import hash_256_filepath


class IntelCommonRequest(APIRequestModel):
    """
    Intel common request data

    provider (str, optional): Provider of the information. Default provider defined by the configuration.
    verbose (bool, optional): Echo back the parameters of the API in the response
    raw (bool, optional): Return additional details from the provider.
    """

    verbose: Optional[bool] = None
    raw: Optional[bool] = None
    provider: Optional[str] = None


class IntelCommonResult(PangeaResponseResult):
    """
    Intel common result data
    """

    parameters: Optional[Dict] = None
    raw_data: Optional[Dict] = None


class IntelReputationData(PangeaResponseResult):
    category: List[str]
    score: int
    verdict: str


class FileReputationRequest(IntelCommonRequest):
    """
    File reputation request data

    hash (str): Hash of the file to be looked up
    hash_type (str): Type of hash, can be "sha256", "sha" or "md5"
    """

    hash: str
    hash_type: str


class FileReputationBulkRequest(APIRequestModel):
    """
    File reputation request data

    hashes (List[str]): Hashes of each file to be looked up
    hash_type (str): Type of hash, can be "sha256", "sha" or "md5"
    """

    hashes: List[str]
    hash_type: str


class FileReputationData(IntelReputationData):
    """
    File reputation information
    """

    pass


class FileReputationResult(IntelCommonResult):
    """
    File reputation result information
    """

    data: FileReputationData


class FileReputationBulkResult(IntelCommonResult):
    """
    File reputation bulk result information
    """

    data: Dict[str, FileReputationData]


class IPCommonRequest(IntelCommonRequest):
    """
    IP common request data
    ip (str): IP address to search for reputation information
    """

    ip: str


class IPCommonBulkRequest(IntelCommonRequest):
    """
    IP common request data
    ips (List[str]): IP addresses to search for reputation information
    """

    ips: List[str]


class IPReputationRequest(IPCommonRequest):
    """
    IP reputation request data

    """

    pass


class IPReputationBulkRequest(IPCommonBulkRequest):
    """
    IP reputation bulk request data

    """

    pass


class IPReputationData(IntelReputationData):
    """
    IP reputation information
    """

    pass


class IPReputationResult(IntelCommonResult):
    """
    IP reputation result
    """

    data: IPReputationData


class IPReputationBulkResult(IntelCommonResult):
    """
    IP reputation result
    """

    data: Dict[str, IPReputationData]


class IPGeolocateRequest(IPCommonRequest):
    """
    IP geolocate request data
    """

    pass


class IPGeolocateBulkRequest(IPCommonBulkRequest):
    """
    IP geolocate bulk request data

    """

    pass


class IPGeolocateData(PangeaResponseResult):
    """
    IP geolocate data
    """

    country: str
    city: str
    latitude: float
    longitude: float
    postal_code: str
    country_code: str


class IPGeolocateResult(IntelCommonResult):
    """
    IP geolocate result
    """

    data: IPGeolocateData


class IPGeolocateBulkResult(IntelCommonResult):
    """
    IP geolocate result
    """

    data: Dict[str, IPGeolocateData]


class IPDomainRequest(IPCommonRequest):
    """
    IP domain request data
    """

    pass


class IPDomainBulkRequest(IPCommonBulkRequest):
    """
    IP domain bulk request data

    """

    pass


class IPDomainData(PangeaResponseResult):
    domain_found: bool
    domain: Optional[str] = None


class IPDomainResult(IntelCommonResult):
    """
    IP domain result
    """

    data: IPDomainData


class IPDomainBulkResult(IntelCommonResult):
    """
    IP domain bulk result
    """

    data: Dict[str, IPDomainData]


class IPVPNRequest(IPCommonRequest):
    """
    IP VPN request data
    """

    pass


class IPVPNBulkRequest(IPCommonBulkRequest):
    """
    IP vpn bulk request data

    """

    pass


class IPVPNData(PangeaResponseResult):
    is_vpn: bool


class IPVPNResult(IntelCommonResult):
    """
    IP VPN result
    """

    data: IPVPNData


class IPVPNBulkResult(IntelCommonResult):
    """
    IP VPN bulk result
    """

    data: Dict[str, IPVPNData]


class IPProxyRequest(IPCommonRequest):
    """
    IP VPN request data
    """

    pass


class IPProxyBulkRequest(IPCommonBulkRequest):
    """
    IP VPN bulk request data
    """

    pass


class IPProxyData(PangeaResponseResult):
    is_proxy: bool


class IPProxyResult(IntelCommonResult):
    """
    IP proxy result
    """

    data: IPProxyData


class IPProxyBulkResult(IntelCommonResult):
    """
    IP proxy bulk result
    """

    data: Dict[str, IPProxyData]


class DomainCommonRequest(IntelCommonRequest):
    """
    Domain lookup request data

    """


class DomainReputationRequest(DomainCommonRequest):
    """
    Domain reputation request data

    domain (str): Domain address to be analyzed
    """

    domain: str


class DomainCommonBulkRequest(DomainCommonRequest):
    """
    Domain common bulk request data

    domain (List[str]): Domain addresses to be analyzed
    """

    domains: List[str]


class DomainReputationBulkRequest(DomainCommonBulkRequest):
    pass


class DomainReputationData(IntelReputationData):
    """
    Domain Reputation information
    """


class DomainReputationResult(IntelCommonResult):
    """
    Domain reputation result
    """

    data: DomainReputationData


class DomainWhoIsRequest(DomainCommonRequest):
    """
    Domain whois request data
    """

    pass


class DomainWhoIsData(PangeaResponseResult):
    """
    Represents information about a domain.

    Attributes:
        domain_name (str): The domain name.
        domain_availability (str): The availability of the domain.
        created_date (str, optional): The date the domain was created.
        updated_date (str, optional): The date the domain was last updated.
        expires_date (str, optional): The date the domain expires.
        host_names (List[str], optional): The host names associated with the domain.
        ips (List[str], optional): The IP addresses associated with the domain.
        registrar_name (str, optional): The name of the registrar.
        contact_email (str, optional): The email address of the contact.
        estimated_domain_age (int, optional): The estimated age of the domain.
        registrant_organization (str, optional): The organization of the registrant.
        registrant_country (str, optional): The country of the registrant.
    """

    domain_name: str
    domain_availability: str
    created_date: Optional[str] = None
    updated_date: Optional[str] = None
    expires_date: Optional[str] = None
    host_names: Optional[List[str]] = None
    ips: Optional[List[str]] = None
    registrar_name: Optional[str] = None
    contact_email: Optional[str] = None
    estimated_domain_age: Optional[int] = None
    registrant_organization: Optional[str] = None
    registrant_country: Optional[str] = None


class DomainWhoIsResult(IntelCommonResult):
    """
    Domain whois result
    """

    data: DomainWhoIsData


class DomainReputationBulkResult(IntelCommonResult):
    """
    Domain reputation bulk result
    """

    data: Dict[str, DomainReputationData]


class URLReputationRequest(IntelCommonRequest):
    """
    URL reputation request data

    url (str): URL address to be analyzed
    """

    url: str


class URLReputationBulkRequest(IntelCommonRequest):
    """
    URL reputation request data

    urls (List[str]): URL addresses to be analyzed
    """

    urls: List[str]


class URLReputationData(IntelReputationData):
    """
    URL reputation information
    """

    pass


class URLReputationResult(IntelCommonResult):
    """
    URL Reputation result
    """

    data: URLReputationData


class URLReputationBulkResult(IntelCommonResult):
    """
    URL Reputation Bulk result
    """

    data: Dict[str, URLReputationData]


class HashType(str, enum.Enum):
    SHA256 = "sha256"
    SHA1 = "sha1"
    SHA512 = "sha512"
    NTLM = "ntlm"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class FileIntel(ServiceBase):
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

    def hash_reputation(
        self,
        hash: str,
        hash_type: str,
        provider: Optional[str] = None,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
    ) -> PangeaResponse[FileReputationResult]:
        """
        Reputation check

        Retrieve a reputation score for a file hash from a provider, including an optional detailed report.

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
            response = file_intel.hash_reputation(
                hash="179e2b8a4162372cd9344b81793cbf74a9513a002eda3324e6331243f3137a63",
                hash_type="sha256",
                provider="reversinglabs",
            )
        """
        input = FileReputationRequest(hash=hash, hash_type=hash_type, verbose=verbose, raw=raw, provider=provider)
        return self.request.post("v1/reputation", FileReputationResult, data=input.model_dump(exclude_none=True))

    def hash_reputation_bulk(
        self,
        hashes: List[str],
        hash_type: str,
        provider: Optional[str] = None,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
    ) -> PangeaResponse[FileReputationBulkResult]:
        """
        Reputation check V2

        Retrieve reputation scores for a set of file hashes from a provider, including an optional detailed report.

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
            response = file_intel.hash_reputation_bulk(
                hashes=["179e2b8a4162372cd9344b81793cbf74a9513a002eda3324e6331243f3137a63"],
                hash_type="sha256",
                provider="reversinglabs",
            )
        """
        input = FileReputationBulkRequest(  # type: ignore[call-arg]
            hashes=hashes, hash_type=hash_type, verbose=verbose, raw=raw, provider=provider
        )
        return self.request.post("v2/reputation", FileReputationBulkResult, data=input.model_dump(exclude_none=True))

    def filepath_reputation(
        self,
        filepath: str,
        provider: Optional[str] = None,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
    ) -> PangeaResponse[FileReputationResult]:
        """
        Reputation, from filepath

        Retrieve a reputation score for a file hash from a provider, including an optional detailed report.
        This function calculates a hash from the file at a given filepath and makes a request to the service.

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
            response = file_intel.filepath_reputation(
                filepath="./myfile.exe",
                provider="reversinglabs",
            )
        """

        with open(filepath, "rb") as data:
            # Can be simplified with `hashlib.file_digest()` in Python v3.11.
            hash = hashlib.sha256(data.read()).hexdigest()

        return self.hash_reputation(hash=hash, hash_type="sha256", verbose=verbose, raw=raw, provider=provider)

    def filepath_reputation_bulk(
        self,
        filepaths: List[str],
        provider: Optional[str] = None,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
    ) -> PangeaResponse[FileReputationBulkResult]:
        """
        Reputation, from filepath V2

        Retrieve reputation scores for a list of file hashes from a provider, including an optional detailed report.
        This function calculates hashes from the files at the given filepaths and makes a request to the service.

        OperationId: file_intel_post_v2_reputation

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
            response = file_intel.filepath_reputation_bulk(
                filepaths=["./myfile.exe"],
                provider="reversinglabs",
            )
        """
        hashes = []
        for filepath in filepaths:
            hash = hash_256_filepath(filepath)
            hashes.append(hash)

        return self.hash_reputation_bulk(hashes=hashes, hash_type="sha256", verbose=verbose, raw=raw, provider=provider)


class DomainIntel(ServiceBase):
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

    def reputation(
        self,
        domain: str,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
        provider: Optional[str] = None,
    ) -> PangeaResponse[DomainReputationResult]:
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
            response = domain_intel.reputation(
                domain="737updatesboeing.com",
                provider="domaintools",
            )
        """
        input = DomainReputationRequest(domain=domain, verbose=verbose, provider=provider, raw=raw)
        return self.request.post("v1/reputation", DomainReputationResult, data=input.model_dump(exclude_none=True))

    def reputation_bulk(
        self,
        domains: List[str],
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
        provider: Optional[str] = None,
    ) -> PangeaResponse[DomainReputationBulkResult]:
        """
        Reputation V2

        Retrieve reputation for a domain from a provider, including an optional detailed report.

        OperationId: domain_intel_post_v2_reputation

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
            response = domain_intel.reputation_bulk(
                domains=["737updatesboeing.com"],
                provider="domaintools",
            )
        """
        input = DomainReputationBulkRequest(domains=domains, verbose=verbose, provider=provider, raw=raw)
        return self.request.post("v2/reputation", DomainReputationBulkResult, data=input.model_dump(exclude_none=True))

    def who_is(
        self, domain: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[DomainWhoIsResult]:
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
            response = domain_intel.who_is(
                domain="google.com",
                provider="whoisxml",
            )
        """
        input = DomainWhoIsRequest(domain=domain, verbose=verbose, provider=provider, raw=raw)  # type: ignore[call-arg]
        return self.request.post("v1/whois", DomainWhoIsResult, data=input.model_dump(exclude_none=True))


class IpIntel(ServiceBase):
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

    def reputation(
        self, ip: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[IPReputationResult]:
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
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/ip-intel)

        Examples:
            response = ip_intel.reputation(
                ip="190.28.74.251",
                provider="crowdstrike",
            )
        """
        input = IPReputationRequest(ip=ip, verbose=verbose, raw=raw, provider=provider)
        return self.request.post("v1/reputation", IPReputationResult, data=input.model_dump(exclude_none=True))

    def reputation_bulk(
        self, ips: List[str], verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[IPReputationBulkResult]:
        """
        Reputation V2

        Retrieve reputation scores for IP addresses from a provider, including an optional detailed report.

        OperationId: ip_intel_post_v2_reputation

        Args:
            ips (List[str]): The IP list to be looked up
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider
            provider (str, optional): Use reputation data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/ip-intel)

        Examples:
            response = ip_intel.reputation_bulk(
                ips=["190.28.74.251"],
                provider="crowdstrike",
            )
        """
        input = IPReputationBulkRequest(ips=ips, verbose=verbose, raw=raw, provider=provider)
        return self.request.post("v2/reputation", IPReputationBulkResult, data=input.model_dump(exclude_none=True))

    def geolocate(
        self, ip: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[IPGeolocateResult]:
        """
        Geolocate

        Retrieve location information associated with an IP address.

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
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/ip-intel)

        Examples:
            response = ip_intel.geolocate(
                ip="93.231.182.110",
                provider="digitalelement",
            )
        """
        input = IPGeolocateRequest(ip=ip, verbose=verbose, raw=raw, provider=provider)
        return self.request.post("v1/geolocate", IPGeolocateResult, data=input.model_dump(exclude_none=True))

    def geolocate_bulk(
        self, ips: List[str], verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[IPGeolocateBulkResult]:
        """
        Geolocate V2

        Retrieve location information associated with an IP address.

        OperationId: ip_intel_post_v2_geolocate

        Args:
            ips (List[str]): List of IP addresses to be geolocated
            provider (str, optional): Use geolocation data from this provider ("digitalelement"). Default provider defined by the configuration.
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the IP information is in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/ip-intel)

        Examples:
            response = ip_intel.geolocate_bulk(
                ips=["93.231.182.110"],
                provider="digitalelement",
            )
        """
        input = IPGeolocateBulkRequest(ips=ips, verbose=verbose, raw=raw, provider=provider)
        return self.request.post("v2/geolocate", IPGeolocateBulkResult, data=input.model_dump(exclude_none=True))

    def get_domain(
        self, ip: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[IPDomainResult]:
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
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/ip-intel)

        Examples:
            response = ip_intel.get_domain(
                ip="93.231.182.110",
                provider="digitalelement",
            )
        """
        input = IPDomainRequest(ip=ip, verbose=verbose, raw=raw, provider=provider)
        return self.request.post("v1/domain", IPDomainResult, data=input.model_dump(exclude_none=True))

    def get_domain_bulk(
        self, ips: List[str], verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[IPDomainBulkResult]:
        """
        Domain V2

        Retrieve the domain names associated with a list of IP addresses.

        OperationId: ip_intel_post_v2_domain

        Args:
            ips (List[str]): List of IPs to be looked up
            provider (str, optional): Use geolocation data from this provider ("digitalelement"). Default provider defined by the configuration.
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the IP information is in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/ip-intel)

        Examples:
            response = ip_intel.get_domain_bulk(
                ips=["93.231.182.110"],
                provider="digitalelement",
            )
        """
        input = IPDomainBulkRequest(ips=ips, verbose=verbose, raw=raw, provider=provider)
        return self.request.post("v2/domain", IPDomainBulkResult, data=input.model_dump(exclude_none=True))

    def is_vpn(
        self, ip: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[IPVPNResult]:
        """
        VPN

        Determine if an IP address originates from a VPN.

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
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/ip-intel)

        Examples:
            response = ip_intel.is_vpn(
                ip="93.231.182.110",
                provider="digitalelement",
            )
        """
        input = IPVPNRequest(ip=ip, verbose=verbose, raw=raw, provider=provider)
        return self.request.post("v1/vpn", IPVPNResult, data=input.model_dump(exclude_none=True))

    def is_vpn_bulk(
        self, ips: List[str], verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[IPVPNBulkResult]:
        """
        VPN V2

        Determine if an IP address originates from a VPN.

        OperationId: ip_intel_post_v2_vpn

        Args:
            ips (List[str]): The IPs list to be looked up
            provider (str, optional): Use geolocation data from this provider ("digitalelement"). Default provider defined by the configuration.
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the IP information is in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/ip-intel)

        Examples:
            response = ip_intel.is_vpn_bulk(
                ip="93.231.182.110",
                provider="digitalelement",
            )
        """
        input = IPVPNBulkRequest(ips=ips, verbose=verbose, raw=raw, provider=provider)
        return self.request.post("v2/vpn", IPVPNBulkResult, data=input.model_dump(exclude_none=True))

    def is_proxy(
        self, ip: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[IPProxyResult]:
        """
        Proxy

        Determine if an IP address originates from a proxy.

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
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/ip-intel)

        Examples:
            response = ip_intel.is_proxy(
                ip="34.201.32.172",
                provider="digitalelement",
            )
        """
        input = IPProxyRequest(ip=ip, verbose=verbose, raw=raw, provider=provider)
        return self.request.post("v1/proxy", IPProxyResult, data=input.model_dump(exclude_none=True))

    def is_proxy_bulk(
        self, ips: List[str], verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[IPProxyBulkResult]:
        """
        Proxy V2

        Determine if an IP address originates from a proxy.

        OperationId: ip_intel_post_v2_proxy

        Args:
            ips (List[str]): The IPs list to be looked up
            provider (str, optional): Use geolocation data from this provider ("digitalelement"). Default provider defined by the configuration.
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the IP information is in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/ip-intel)

        Examples:
            response = ip_intel.is_proxy_bulk(
                ips=["34.201.32.172"],
                provider="digitalelement",
            )
        """
        input = IPProxyBulkRequest(ips=ips, verbose=verbose, raw=raw, provider=provider)
        return self.request.post("v2/proxy", IPProxyBulkResult, data=input.model_dump(exclude_none=True))


class UrlIntel(ServiceBase):
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

    def reputation(
        self,
        url: str,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
        provider: Optional[str] = None,
    ) -> PangeaResponse[URLReputationResult]:
        """
        Reputation

        Retrieve a reputation score for a URL from a provider, including an optional detailed report.

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
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/url-intel)

        Examples:
            response = url_intel.reputation(
                url="http://113.235.101.11:54384",
                provider="crowdstrike",
            )
        """

        input = URLReputationRequest(url=url, provider=provider, verbose=verbose, raw=raw)
        return self.request.post("v1/reputation", URLReputationResult, data=input.model_dump(exclude_none=True))

    def reputation_bulk(
        self,
        urls: List[str],
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
        provider: Optional[str] = None,
    ) -> PangeaResponse[URLReputationBulkResult]:
        """
        Reputation V2

        Retrieve reputation scores for a list of URLs from a provider, including an optional detailed report.

        OperationId: url_intel_post_v2_reputation

        Args:
            urls (List[str]): The URL list to be looked up
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider
            provider (str, optional): Use reputation data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/url-intel)

        Examples:
            response = url_intel.reputation_bulk(
                urls=["http://113.235.101.11:54384"],
                provider="crowdstrike",
            )
        """

        input = URLReputationBulkRequest(urls=urls, provider=provider, verbose=verbose, raw=raw)
        return self.request.post("v2/reputation", URLReputationBulkResult, data=input.model_dump(exclude_none=True))


class UserBreachedRequest(IntelCommonRequest):
    """
    User breached request data

    email (str): An email address to search for
    username (str): An username to search for
    ip (str): An ip to search for
    phone_number (str): A phone number to search for. minLength: 7, maxLength: 15.
    start (str): Earliest date for search
    end (str): Latest date for search
    cursor (str, optional): A token given in the raw response from SpyCloud. Post this back to paginate results
    """

    email: Optional[str] = None
    username: Optional[str] = None
    ip: Optional[str] = None
    phone_number: Optional[str] = None
    start: Optional[str] = None
    end: Optional[str] = None
    cursor: Optional[str] = None

    severity: Optional[List[int]] = None
    """Filter for records that match one of the given severities"""


class UserBreachedBulkRequest(IntelCommonRequest):
    """
    User breached request data

    emails (List[str]): An email address' list to search for
    usernames (List[str]): An username' list to search for
    ips (List[str]): An ip's list to search for
    phone_numbers (List[str]): A phone number's list to search for. minLength: 7, maxLength: 15.
    domains (List[str]): Search for user under these domains.
    start (str): Earliest date for search
    end (str): Latest date for search
    """

    emails: Optional[List[str]] = None
    usernames: Optional[List[str]] = None
    ips: Optional[List[str]] = None
    phone_numbers: Optional[List[str]] = None
    domains: Optional[List[str]] = None
    start: Optional[str] = None
    end: Optional[str] = None

    severity: Optional[List[int]] = None
    """Filter for records that match one of the given severities"""


class UserBreachedCommonData(PangeaResponseResult):
    """
    User breached common information
    """

    found_in_breach: bool
    breach_count: int


class UserBreachedData(UserBreachedCommonData):
    """
    User breached information
    """

    pass


class UserBreachedResult(IntelCommonResult):
    """
    User breached result
    """

    data: UserBreachedData


class UserBreachedBulkResult(IntelCommonResult):
    """
    User breached result
    """

    data: Dict[str, UserBreachedData]


class UserPasswordBreachedRequest(IntelCommonRequest):
    """
    User password breached common request data

    hash_type (str): Hash type to be looked up
    hash_prefix (str): The prefix of the hash to be looked up.
    """

    hash_type: str
    hash_prefix: str


class UserPasswordBreachedBulkRequest(IntelCommonRequest):
    """
    User password breached bulk request data

    hash_type (str): Hash type to be looked up
    hash_prefixes (List[str]): The list of prefixes of the hashes to be looked up.
    """

    hash_type: str
    hash_prefixes: List[str]


class UserPasswordBreachedData(UserBreachedCommonData):
    """
    User password breached information
    """

    pass


class UserPasswordBreachedResult(IntelCommonResult):
    """
    User password breached result
    """

    data: UserPasswordBreachedData


class UserPasswordBreachedBulkResult(IntelCommonResult):
    """
    User password breached bulk result
    """

    data: Dict[str, UserPasswordBreachedData]


class BreachRequest(APIRequestModel):
    """Breach request data"""

    breach_id: Optional[str] = None
    """The ID of a breach returned by a provider."""

    verbose: Optional[bool] = None
    """Echo back the parameters of the API in the response."""

    provider: Optional[str] = None
    """Provider of the information. Default provider defined by the configuration."""

    severity: Optional[List[int]] = None
    """Filter for records that match one of the given severities"""

    start: Optional[str] = None
    """This parameter allows you to define the starting point for a date range query on the spycloud_publish_date field."""

    end: Optional[str] = None
    """This parameter allows you to define the ending point for a date range query on the spycloud_publish_date field."""

    cursor: Optional[str] = None
    """A token given in the raw response from SpyCloud. Post this back to paginate results"""


class BreachResult(PangeaResponseResult):
    """Breach result"""

    found: bool
    """A flag indicating if the lookup was successful."""

    data: Optional[Dict] = None
    """Breach details given by the provider."""

    parameters: Optional[Dict] = None
    """The parameters, which were passed in the request, echoed back."""


class UserIntel(ServiceBase):
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

    def user_breached(
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
        severity: Optional[List[int]] = None,
    ) -> PangeaResponse[UserBreachedResult]:
        """
        Look up breached users

        Determine if an email address, username, phone number, or IP address was exposed in a security breach.

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
            severity (List[int], optional): Filter for records that match one of the given severities

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/user-intel)

        Examples:
            response = user_intel.user_breached(
                phone_number="8005550123",
                provider="spycloud",
                verbose=True,
                raw=True,
            )
        """

        input = UserBreachedRequest(
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
            severity=severity,
        )
        return self.request.post("v1/user/breached", UserBreachedResult, data=input.model_dump(exclude_none=True))

    def user_breached_bulk(
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
        severity: Optional[List[int]] = None,
    ) -> PangeaResponse[UserBreachedBulkResult]:
        """
        Look up breached users V2

        Determine if an email address, username, phone number, or IP address was exposed in a security breach.

        OperationId: user_intel_post_v2_user_breached

        Args:
            emails (List[str]): A list of email addresses to search for
            usernames (List[str]): A list of usernames to search for
            ips (List[str]): A list of ips to search for
            phone_numbers (List[str]): A list of phone numbers to search for. minLength: 7, maxLength: 15.
            domains (List[str]): Search for user under these domains.
            start (str): Earliest date for search
            end (str): Latest date for search
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider
            provider (str, optional): Use reputation data from this provider
            severity (List[int], optional): Filter for records that match one of the given severities

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/user-intel)

        Examples:
            response = user_intel.user_breached_bulk(
                phone_numbers=["8005550123"],
                provider="spycloud",
                verbose=True,
                raw=True,
            )
        """

        input = UserBreachedBulkRequest(
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
            severity=severity,
        )
        return self.request.post("v2/user/breached", UserBreachedBulkResult, data=input.model_dump(exclude_none=True))

    def password_breached(
        self,
        hash_type: HashType,
        hash_prefix: str,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = True,
        provider: Optional[str] = None,
    ) -> PangeaResponse[UserPasswordBreachedResult]:
        """
        Look up breached passwords

        Determine if a password has been exposed in a security breach using a 5 character prefix of the password hash.

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
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/user-intel)

        Examples:
            response = user_intel.password_breached(
                hash_prefix="5baa6",
                hash_type=HashType.SHA256,
                provider="spycloud",
            )
        """

        input = UserPasswordBreachedRequest(
            hash_type=hash_type, hash_prefix=hash_prefix, provider=provider, verbose=verbose, raw=raw
        )
        return self.request.post(
            "v1/password/breached", UserPasswordBreachedResult, data=input.model_dump(exclude_none=True)
        )

    def password_breached_bulk(
        self,
        hash_type: HashType,
        hash_prefixes: List[str],
        verbose: Optional[bool] = None,
        raw: Optional[bool] = True,
        provider: Optional[str] = None,
    ) -> PangeaResponse[UserPasswordBreachedBulkResult]:
        """
        Look up breached passwords V2

        Determine if a password has been exposed in a security breach using a 5 character prefix of the password hash.

        OperationId: user_intel_post_v2_password_breached

        Args:
            hash_type (str): Hash type to be looked up
            hash_prefixes (List[str]): The list of prefixes of the hashes to be looked up.
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider
            provider (str, optional): Use reputation data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/user-intel)

        Examples:
            response = user_intel.password_breached_bulk(
                hash_prefixes=["5baa6"],
                hash_type=HashType.SHA256,
                provider="spycloud",
            )
        """

        input = UserPasswordBreachedBulkRequest(
            hash_type=hash_type, hash_prefixes=hash_prefixes, provider=provider, verbose=verbose, raw=raw
        )
        return self.request.post(
            "v2/password/breached", UserPasswordBreachedBulkResult, data=input.model_dump(exclude_none=True)
        )

    def breach(
        self,
        breach_id: Optional[str] = None,
        verbose: Optional[bool] = None,
        provider: Optional[str] = None,
        cursor: Optional[str] = None,
        start: Optional[str] = None,
        end: Optional[str] = None,
        severity: Optional[List[int]] = None,
    ) -> PangeaResponse[BreachResult]:
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
            response = user_intel.breach(
                breach_id="66111",
            )
        """

        input = BreachRequest(
            breach_id=breach_id,
            provider=provider,
            verbose=verbose,
            cursor=cursor,
            start=start,
            end=end,
            severity=severity,
        )
        return self.request.post("v1/breach", BreachResult, data=input.model_dump(exclude_none=True))

    class PasswordStatus(enum.Enum):
        BREACHED = 0
        UNBREACHED = 1
        INCONCLUSIVE = 2

    @staticmethod
    def is_password_breached(response: PangeaResponse[UserBreachedResult], hash: str) -> PasswordStatus:
        """
        Check if a password was breached

        Helper function that simplifies searching the response's raw data for
        the full hash.

        Args:
            response: API response from an earlier request
            hash: Password hash
        """

        if response.result.raw_data is None:  # type: ignore[union-attr]
            raise PangeaException("Need raw data to check if hash is breached. Send request with raw=true")

        hash_data = response.result.raw_data.pop(hash, None)  # type: ignore[union-attr]
        if hash_data is not None:
            # If hash is present in raw data, it's because it was breached
            return UserIntel.PasswordStatus.BREACHED
        else:
            # If it's not present, should check if I have all breached hash
            # Server will return a maximum of 1000 hash, so if breached count is greater than that,
            # I can't conclude is password is or is not breached
            if len(response.result.raw_data.keys()) >= 1000:  # type: ignore[union-attr]
                return UserIntel.PasswordStatus.INCONCLUSIVE
            else:
                return UserIntel.PasswordStatus.UNBREACHED

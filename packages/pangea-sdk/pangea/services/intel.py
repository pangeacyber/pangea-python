# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import hashlib
from typing import Dict, List, Optional

from pangea.deprecated import pangea_deprecated
from pangea.response import APIRequestModel, APIResponseModel, PangeaResponse, PangeaResponseResult

from .base import ServiceBase


class FileReputationRequest(APIRequestModel):
    """
    File reputation request data

    file_hash (str): Hash of the file to be looked up
    hash_type (str): Type of hash, can be "sha256", "sha" or "md5"
    provider (str, optional): Provider of the reputation information.  ("reversinglabs"). Default provider defined by the configuration.
    verbose (bool, optional): Echo back the parameters of the API in the response
    raw (bool, optional): Return additional details from the provider.
    """

    hash: str
    hash_type: str
    verbose: Optional[bool] = None
    raw: Optional[bool] = None
    provider: Optional[str] = None


class FileLookupRequest(FileReputationRequest):
    pass


class FileReputationData(APIResponseModel):
    """
    File reputation information
    """

    category: List[str]
    score: int
    verdict: str


class FileReputationResult(PangeaResponseResult):
    """
    File reputation result information
    """

    data: FileReputationData
    parameters: Optional[Dict] = None
    raw_data: Optional[Dict] = None


class FileLookupResult(FileReputationResult):
    pass


class IPRepurationRequest(APIRequestModel):
    """
    IP reputation request data

    ip (str): IP address to search for reputation information
    provider (str, optional): Provider of the reputation information. ("reversinglabs"). Default provider defined by the configuration.
    verbose (bool, optional): Echo back the parameters of the API in the response
    raw (bool, optional): Return additional details from the provider.
    """

    ip: str
    verbose: Optional[bool] = None
    raw: Optional[bool] = None
    provider: Optional[str] = None


class IPLookupRequest(IPRepurationRequest):
    pass


class IPReputationData(APIResponseModel):
    """
    IP reputation information
    """

    category: List[str]
    score: int
    verdict: str


class IPReputationResult(PangeaResponseResult):
    """
    IP lookup result
    """

    data: IPReputationData
    parameters: Optional[Dict] = None
    raw_data: Optional[Dict] = None


class IPLookupResult(IPReputationResult):
    pass


class DomainReputationRequest(APIRequestModel):
    """
    Domain reputation request data

    domain (str): Domain address to search for reputation information
    provider (str, optional): Provider of the reputation information. ("domaintools"). Default provider defined by the configuration.
    verbose (bool, optional): Echo back the parameters of the API in the response
    raw (bool, optional): Return additional details from the provider.
    """

    domain: str
    verbose: Optional[bool] = None
    raw: Optional[bool] = None
    provider: Optional[str] = None


class DomainLookupRequest(DomainReputationRequest):
    pass


class DomainReputationData(APIResponseModel):
    """
    Domain Reputation information
    """

    category: List[str]
    score: int
    verdict: str


class DomainReputationResult(PangeaResponseResult):
    """
    Domain reputation result
    """

    data: DomainReputationData
    parameters: Optional[Dict] = None
    raw_data: Optional[Dict] = None


class DomainLookupResult(DomainReputationResult):
    pass


class URLReputationRequest(APIRequestModel):
    """
    URL reputation request data

    url (str): URL address to search for reputation information
    provider (str, optional): Provider of the reputation information. ("crowdstrike"). Default provider defined by the configuration.
    verbose (bool, optional): Echo back the parameters of the API in the response
    raw (bool, optional): Return additional details from the provider.
    """

    url: str
    verbose: Optional[bool] = None
    raw: Optional[bool] = None
    provider: Optional[str] = None


class URLLookupRequest(URLReputationRequest):
    pass


class URLReputationData(APIResponseModel):
    """
    URL reputation information
    """

    category: List[str]
    score: int
    verdict: str


class URLReputationResult(PangeaResponseResult):
    """
    URL lookup result
    """

    data: URLReputationData
    parameters: Optional[Dict] = None
    raw_data: Optional[Dict] = None


class URLLookupResult(URLReputationResult):
    pass


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
    version = "v1"

    @pangea_deprecated(version="1.2.0", reason="Should use FileIntel.hashReputation()")
    def lookup(
        self,
        hash: str,
        hash_type: str,
        provider: Optional[str] = None,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
    ) -> PangeaResponse[FileLookupResult]:
        """
        Look up a file

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
            response = file_intel.lookup(hash="142b638c6a60b60c7f9928da4fb85a5a8e1422a9ffdc9ee49e17e56ccca9cf6e", hash_type="sha256", provider="reversinglabs")

        """
        input = FileReputationRequest(hash=hash, hash_type=hash_type, verbose=verbose, raw=raw, provider=provider)
        response = self.request.post("reputation", data=input.dict(exclude_none=True))
        response.result = FileLookupResult(**response.raw_result)
        return response

    def hashReputation(
        self,
        hash: str,
        hash_type: str,
        provider: Optional[str] = None,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
    ) -> PangeaResponse[FileReputationResult]:
        """
        Look up a file hash reputation

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
            response = file_intel.hashReputation(hash="142b638c6a60b60c7f9928da4fb85a5a8e1422a9ffdc9ee49e17e56ccca9cf6e", hash_type="sha256", provider="reversinglabs")

        """
        input = FileReputationRequest(hash=hash, hash_type=hash_type, verbose=verbose, raw=raw, provider=provider)
        response = self.request.post("reputation", data=input.dict(exclude_none=True))
        response.result = FileReputationResult(**response.raw_result)
        return response

    @pangea_deprecated(version="1.2.0", reason="Should use FileIntel.filepathReputation()")
    def lookupFilepath(
        self,
        filepath: str,
        provider: Optional[str] = None,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
    ) -> PangeaResponse[FileLookupResult]:
        """
        Look up a filepath

        Retrieve hash-based file reputation from a provider, including an optional detailed report.

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
            response = file_intel.lookupFilepath(filepath="./myfile.exe", provider="reversinglabs"))
        """

        data = open(filepath, "rb")
        hash = hashlib.sha256(data.read()).hexdigest()

        input = FileReputationRequest(hash=hash, hash_type="sha256", verbose=verbose, raw=raw, provider=provider)
        response = self.request.post("reputation", data=input.dict(exclude_none=True))
        response.result = FileLookupResult(**response.raw_result)
        return response

    def filepathReputation(
        self,
        filepath: str,
        provider: Optional[str] = None,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
    ) -> PangeaResponse[FileReputationResult]:
        """
        Look up a filepath reputation

        Retrieve hash-based file reputation from a provider, including an optional detailed report.
        This function take care of calculate filepath hash and make the request to service

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
            response = file_intel.filepathReputation(filepath="./myfile.exe", provider="reversinglabs"))
        """

        data = open(filepath, "rb")
        hash = hashlib.sha256(data.read()).hexdigest()

        input = FileReputationRequest(hash=hash, hash_type="sha256", verbose=verbose, raw=raw, provider=provider)
        response = self.request.post("reputation", data=input.dict(exclude_none=True))
        response.result = FileReputationResult(**response.raw_result)
        return response


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
    version = "v1"

    @pangea_deprecated(version="1.2.0", reason="Should use DomainIntel.reputation()")
    def lookup(
        self, domain: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[DomainLookupResult]:
        """
        Look up a domain

        Retrieve reputation for a domain from a provider, including an optional detailed report.

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
            response = domain_intel.lookup(domain="737updatesboeing.com", provider="domaintools")
        """
        input = DomainReputationRequest(domain=domain, verbose=verbose, provider=provider, raw=raw)
        response = self.request.post("reputation", data=input.dict(exclude_none=True))
        response.result = DomainLookupResult(**response.raw_result)
        return response

    def reputation(
        self, domain: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[DomainReputationResult]:
        """
        Look up a domain reputation

        Retrieve reputation for a domain from a provider, including an optional detailed report.

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
            response = domain_intel.lookup(domain="737updatesboeing.com", provider="domaintools")
        """
        input = DomainReputationRequest(domain=domain, verbose=verbose, provider=provider, raw=raw)
        response = self.request.post("reputation", data=input.dict(exclude_none=True))
        response.result = DomainReputationResult(**response.raw_result)
        return response


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
    version = "v1"

    @pangea_deprecated(version="1.2.0", reason="Should use IpIntel.reputation()")
    def lookup(
        self, ip: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[IPReputationResult]:
        """
        Look up an IP

        Retrieve a reputation score for an IP address from a provider, including an optional detailed report.

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
            response = ip_intel.lookup(ip="93.231.182.110", provider="crowdstrike")

        """
        input = IPRepurationRequest(ip=ip, verbose=verbose, raw=raw, provider=provider)
        response = self.request.post("reputation", data=input.dict(exclude_none=True))
        response.result = IPReputationResult(**response.raw_result)
        return response

    def reputation(
        self, ip: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[IPReputationResult]:
        """
        Look up an IP reputation

        Retrieve a reputation score for an IP address from a provider, including an optional detailed report.

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
            response = ip_intel.reputation(ip="93.231.182.110", provider="crowdstrike")
        """
        input = IPRepurationRequest(ip=ip, verbose=verbose, raw=raw, provider=provider)
        response = self.request.post("reputation", data=input.dict(exclude_none=True))
        response.result = IPReputationResult(**response.raw_result)
        return response


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
    version = "v1"

    @pangea_deprecated(version="1.2.0", reason="Should use UrlIntel.reputation()")
    def lookup(
        self, url: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[URLLookupResult]:
        """
        Look up a URL

        Retrieve URL address reputation from a provider.

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
            response = url_intel.lookup(url="http://113.235.101.11:54384", provider="crowdstrike")
        """

        input = URLReputationRequest(url=url, provider=provider, verbose=verbose, raw=raw)
        response = self.request.post("reputation", data=input.dict(exclude_none=True))
        response.result = URLLookupResult(**response.raw_result)
        return response

    def reputation(
        self, url: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[URLReputationResult]:
        """
        Look up a URL reputation

        Retrieve URL address reputation from a provider.

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
            response = url_intel.reputation(url="http://113.235.101.11:54384", provider="crowdstrike")
        """

        input = URLReputationRequest(url=url, provider=provider, verbose=verbose, raw=raw)
        response = self.request.post("reputation", data=input.dict(exclude_none=True))
        response.result = URLReputationResult(**response.raw_result)
        return response

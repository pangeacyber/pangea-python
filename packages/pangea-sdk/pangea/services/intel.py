# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import hashlib
from typing import Dict, List, Optional

from pangea.response import APIRequestModel, APIResponseModel, PangeaResponse, PangeaResponseResult

from .base import ServiceBase


class FileLookupRequest(APIRequestModel):
    """
    File lookup request data

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


class FileLookupData(APIResponseModel):
    """
    File lookup information
    """

    category: List[str]
    score: int
    verdict: str


class FileLookupResult(PangeaResponseResult):
    """
    File lookup result information
    """

    data: FileLookupData
    parameters: Optional[Dict] = None
    raw_data: Optional[Dict] = None


class IPLookupRequest(APIRequestModel):
    """
    IP lookup request data

    ip (str): IP address to be looked up
    provider (str, optional): Provider of the reputation information. ("reversinglabs"). Default provider defined by the configuration.
    verbose (bool, optional): Echo back the parameters of the API in the response
    raw (bool, optional): Return additional details from the provider.
    """

    ip: str
    verbose: Optional[bool] = None
    raw: Optional[bool] = None
    provider: Optional[str] = None


class IPLookupData(APIResponseModel):
    """
    IP lookup information
    """

    category: List[str]
    score: int
    verdict: str


class IPLookupResult(PangeaResponseResult):
    """
    IP lookup result
    """

    data: IPLookupData
    parameters: Optional[Dict] = None
    raw_data: Optional[Dict] = None


class DomainLookupRequest(APIRequestModel):
    """
    Domain lookup request data

    domain (str): Domain address to be looked up
    provider (str, optional): Provider of the reputation information. ("domaintools"). Default provider defined by the configuration.
    verbose (bool, optional): Echo back the parameters of the API in the response
    raw (bool, optional): Return additional details from the provider.
    """

    domain: str
    verbose: Optional[bool] = None
    raw: Optional[bool] = None
    provider: Optional[str] = None


class DomainLookupData(APIResponseModel):
    """
    Domain lookup information
    """

    category: List[str]
    score: int
    verdict: str


class DomainLookupResult(PangeaResponseResult):
    """
    Domain lookup result
    """

    data: DomainLookupData
    parameters: Optional[Dict] = None
    raw_data: Optional[Dict] = None


class URLLookupRequest(APIRequestModel):
    """
    URL lookup request data

    url (str): URL address to be looked up
    provider (str, optional): Provider of the reputation information. ("crowdstrike"). Default provider defined by the configuration.
    verbose (bool, optional): Echo back the parameters of the API in the response
    raw (bool, optional): Return additional details from the provider.
    """

    url: str
    verbose: Optional[bool] = None
    raw: Optional[bool] = None
    provider: Optional[str] = None


class URLLookupData(APIResponseModel):
    """
    URL lookup information
    """

    category: List[str]
    score: int
    verdict: str


class URLLookupResult(PangeaResponseResult):
    """
    URL lookup result
    """

    data: URLLookupData
    parameters: Optional[Dict] = None
    raw_data: Optional[Dict] = None


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

        Retrieve file reputation from a provider, using the file's hash.

        Args:
            hash (str): hash to perform lookup
            hash_type (str): hash type of hash parameter
            provider (str, optional): intel provider to perfome lookup
            verbose (bool, optional): true to get more detalied response
            raw (bool, optional): true to get provider raw response

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/file-intel).

        Examples:
            response = file_intel.lookup(hash="142b638c6a60b60c7f9928da4fb85a5a8e1422a9ffdc9ee49e17e56ccca9cf6e", hash_type="sha256", provider="reversinglabs")

            \"\"\"
            response contains:
            {
                "request_id": "prq_snooq62g4jsolhhpm4ze6pgzhmguflnl",
                "request_time": "2022-10-10T21:54:19.392Z",
                "response_time": "2022-10-10T21:54:19.933Z",
                "status": "Success",
                "summary": "Hash was found",
                "result": {
                    "data": {
                        "category": [
                            "Trojan"
                        ],
                        "score": 100,
                        "verdict": "malicious"
                    }
                }
            }
            \"\"\"
        """
        input = FileLookupRequest(hash=hash, hash_type=hash_type, verbose=verbose, raw=raw, provider=provider)
        response = self.request.post("lookup", data=input.dict(exclude_none=True))
        response.result = FileLookupResult(**response.raw_result)
        return response

    def lookupFilepath(
        self,
        filepath: str,
        provider: Optional[str] = None,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
    ) -> PangeaResponse[FileLookupResult]:
        """
        Look up a file

        Retrieve file reputation from a provider, using the file's hash.

        Args:
            filepath (str): path file to calculate hash and request a lookup
            provider (str, optional): intel provider to perfome lookup
            verbose (bool, optional): true to get more detalied response
            raw (bool, optional): true to get provider raw response

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/file-intel).

        Examples:
            response = file_intel.lookup(filepath="./myfile.exe", provider="reversinglabs"))

            \"\"\"
            response contains:
            {
                "request_id": "prq_snooq62g4jsolhhpm4ze6pgzhmguflnl",
                "request_time": "2022-10-10T21:54:19.392Z",
                "response_time": "2022-10-10T21:54:19.933Z",
                "status": "Success",
                "summary": "Hash was found",
                "result": {
                    "data": {
                        "category": [
                            "Trojan"
                        ],
                        "score": 100,
                        "verdict": "malicious"
                    }
                }
            }
            \"\"\"
        """

        data = open(filepath, "rb")
        hash = hashlib.sha256(data.read()).hexdigest()

        input = FileLookupRequest(hash=hash, hash_type="sha256", verbose=verbose, raw=raw, provider=provider)
        response = self.request.post("lookup", data=input.dict(exclude_none=True))
        response.result = FileLookupResult(**response.raw_result)
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

    def lookup(
        self, domain: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[DomainLookupResult]:
        """
        Look up a domain

        Retrieve Domain reputation from a provider.

        Args:
            domain (str): domain to request for a lookup
            provider (str, optional): intel provider to perfome lookup
            verbose (bool, optional): true to get more detalied response
            raw (bool, optional): true to get provider raw response

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/domain-intel).

        Examples:
            response = domain_intel.lookup(domain="737updatesboeing.com", provider="domaintools")

            \"\"\"
            response contains:
            {
                "request_id": "prq_gs5konqehibr5zflkxeqe2l2z7haeirx",
                "request_time": "2022-10-10T21:57:08.860Z",
                "response_time": "2022-10-10T21:57:09.539Z",
                "status": "Success",
                "summary": "Domain was found",
                "result": {
                    "data": {
                        "category": [
                            "sinkhole",
                            "proximity",
                            "threat_profile",
                            "threat_profile_phishing",
                            "threat_profile_malware",
                            "threat_profile_spam"
                        ],
                        "score": 100,
                        "verdict": "malicious"
                    }
                }
            }
            \"\"\"
        """
        input = DomainLookupRequest(domain=domain, verbose=verbose, provider=provider, raw=raw)
        response = self.request.post("lookup", data=input.dict(exclude_none=True))
        response.result = DomainLookupResult(**response.raw_result)
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

    def lookup(
        self, ip: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[IPLookupResult]:
        """
        Retrieve IP address reputation from a provider.

        Args:
            input (IPLookupInput): input with IP information to perform request

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/ip-intel)

        Examples:
            response = ip_intel.lookup(IPLookupInput(ip="93.231.182.110", provider="crowdstrike"))

            \"\"\"
            response contains:
            {
                "request_id": "prq_xoohakngaerteg4yiekikva3issxp4bq",
                "request_time": "2022-08-23T03:28:20.225Z",
                "response_time": "2022-08-23T03:28:20.244Z",
                "status": "success",
                "summary": "IP was found",
                "result": {
                    "data": {
                        "category": [
                            "Suspicious"
                        ],
                        "score": 0,
                        "verdict": "malicious"
                    }
                }
            }
            \"\"\"
        """
        input = IPLookupRequest(ip=ip, verbose=verbose, raw=raw, provider=provider)
        response = self.request.post("lookup", data=input.dict(exclude_none=True))
        response.result = IPLookupResult(**response.raw_result)
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

    def lookup(
        self, url: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[URLLookupResult]:
        """
        Retrieve URL address reputation from a provider.

        Args:
            input (URLLookupInput): input with URL information to perform request

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/url-intel)

        Examples:
            response = url_intel.lookup(URLLookupInput(url="http://113.235.101.11:54384", provider="crowdstrike"))

            \"\"\"
            response contains:
            {
                "request_id": "prq_5ugxruda7vmsgioup6vjvaqmnmvxzbqv",
                "request_time": "2022-08-23T03:40:03.549Z",
                "response_time": "2022-08-23T03:40:03.694Z",
                "status": "success",
                "summary": "Url was found",
                "result": {
                    "data": {
                        "category": [
                            "Not Provided"
                        ],
                        "score": 80,
                        "verdict": "malicious"
                    }
                }
            }
            \"\"\"
        """

        input = URLLookupRequest(url=url, provider=provider, verbose=verbose, raw=raw)
        response = self.request.post("lookup", data=input.dict(exclude_none=True))
        response.result = URLLookupResult(**response.raw_result)
        return response

# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from dataclasses import dataclass
from typing import Dict, List, Optional

from pydantic import BaseModel

from pangea.response import PangeaResponse

from .base import ServiceBase


@dataclass
class FileLookupInput(BaseModel):
    """
    TODO: complete
    """

    hash: str
    hash_type: str
    verbose: Optional[bool] = None
    raw: Optional[bool] = None
    provider: Optional[str] = None


@dataclass
class FileLookupData(BaseModel):
    """
    TODO: complete
    """

    category: List[str]
    score: int
    verdict: str


@dataclass
class FileLookupOutput(BaseModel):
    """
    TODO: complete
    """

    data: FileLookupData
    parameters: Optional[Dict] = None
    raw_data: Optional[Dict] = None


@dataclass
class IPLookupInput(BaseModel):
    """
    TODO: complete
    """

    ip: str
    verbose: Optional[bool] = None
    raw: Optional[bool] = None
    provider: Optional[str] = None


@dataclass
class IPLookupData(BaseModel):
    """
    TODO: complete
    """

    category: List[str]
    score: int
    verdict: str


@dataclass
class IPLookupOutput(BaseModel):
    """
    TODO: complete
    """

    data: IPLookupData
    parameters: Optional[Dict] = None
    raw_data: Optional[Dict] = None


@dataclass
class DomainLookupInput(BaseModel):
    """
    TODO: complete
    """

    domain: str
    verbose: Optional[bool] = None
    raw: Optional[bool] = None
    provider: Optional[str] = None


@dataclass
class DomainLookupData(BaseModel):
    """
    TODO: complete
    """

    category: List[str]
    score: int
    verdict: str


@dataclass
class DomainLookupOutput(BaseModel):
    """
    TODO: complete
    """

    data: DomainLookupData
    parameters: Optional[Dict] = None
    raw_data: Optional[Dict] = None


@dataclass
class URLLookupInput(BaseModel):
    """
    TODO: complete
    """

    url: str
    verbose: Optional[bool] = None
    raw: Optional[bool] = None
    provider: Optional[str] = None


@dataclass
class URLLookupData(BaseModel):
    """
    TODO: complete
    """

    category: List[str]
    score: int
    verdict: str


@dataclass
class URLLookupOutput(BaseModel):
    """
    TODO: complete
    """

    data: URLLookupData
    parameters: Optional[Dict] = None
    raw_data: Optional[Dict] = None


class FileIntel(ServiceBase):
    """File Intel service client

    Provides methods to interact with [Pangea File Intel Service](/docs/api/file-intel)

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)
        FILE_INTEL_CONFIG_ID - Configuration ID which can be found on the Pangea
            User Console at [https://console.pangea.cloud/service/file-intel](https://console.pangea.cloud/service/file-intel)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import FileIntel

        PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")
        FILE_INTEL_CONFIG_ID = os.getenv("FILE_INTEL_CONFIG_ID")

        file_intel_config = PangeaConfig(domain="pangea.cloud",
                                        config_id=FILE_INTEL_CONFIG_ID)

        # Setup Pangea File Intel service
        file_intel = FileIntel(token=PANGEA_TOKEN, config=file_intel_config)
    """

    service_name = "file-intel"
    version = "v1"

    def lookup(
        self, file_hash: str, hash_type: str, provider: str = None, verbose: bool = False, raw: bool = False
    ) -> PangeaResponse:
        """
        Lookup file reputation by hash.

        Retrieve file reputation from a provider, using the file's hash.

        Args:
            file_hash (str): Hash of the file to be looked up
            hash_type (str): Type of hash, can be "sha256", "sha" or "md5"
            provider (str, optional): Provider of the reputation information. ("reversinglabs" or "crowdstrike"). Default provider defined by the configuration.
            verbose (bool, optional): Echo back the parameters of the API in the response
            raw (bool, optional): Return additional details from the provider.

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/file-intel).

        Examples:
            response = file_intel.lookup("322ccbd42b7e4fd3a9d0167ca2fa9f6483d9691364c431625f1df54270647ca8", "sha256", provider="crowdstrike")

            \"\"\"
            response contains:
            {
                "request_id": "prq_shfq6vhj7xvi6b6noswfkuoeaxtzgpnb",
                "request_time": "2022-08-23T02:43:17.614Z",
                "response_time": "2022-08-23T02:43:18.607Z",
                "status": "success",
                "status_code": 200,
                "summary": "Hash was found",
                "result": {
                    "data": {
                        "category": [
                            "RAT",
                            "Targeted"
                        ],
                        "score": 80,
                        "verdict": "malicious"
                    }
                }
            }
            \"\"\"
        """

        data = {
            "hash": file_hash,
            "hash_type": hash_type,
        }
        if provider:
            data["provider"] = provider
        if verbose:
            data["verbose"] = verbose
        if raw:
            data["raw"] = raw

        return self.request.post("lookup", data=data)


class IpIntel(ServiceBase):
    """IP Intel service client

    Provides methods to interact with [Pangea IP Intel Service](/docs/api/ip-intel)

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)
        IP_INTEL_CONFIG_ID - Configuration ID which can be found on the Pangea
            User Console at [https://console.pangea.cloud/service/ip-intel](https://console.pangea.cloud/service/ip-intel)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import IpIntel

        PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")
        IP_INTEL_CONFIG_ID = os.getenv("IP_INTEL_CONFIG_ID")

        ip_intel_config = PangeaConfig(domain="pangea.cloud",
                                        config_id=IP_INTEL_CONFIG_ID)

        # Setup Pangea IP Intel service
        ip_intel = IpIntel(token=PANGEA_TOKEN, config=ip_intel_config)
    """

    service_name = "ip-intel"
    version = "v1"

    def lookup(self, ip: str, provider: str = None, verbose: bool = False, raw: bool = False) -> PangeaResponse:
        """
        Retrieve IP address reputation from a provider.

        Args:
            ip (str): IP address to be looked up
            provider (str, optional): Provider of the reputation information. ("crowdstrike"). Default provider defined by the configuration.
            verbose (bool, optional): Echo back the parameters of the API in the response
            raw (bool, optional): Return additional details from the provider.

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/ip-intel)

        Examples:
            response = ip_intel.lookup("93.231.182.110", provider="crowdstrike")

            \"\"\"
            response contains:
            {
                "request_id": "prq_xoohakngaerteg4yiekikva3issxp4bq",
                "request_time": "2022-08-23T03:28:20.225Z",
                "response_time": "2022-08-23T03:28:20.244Z",
                "status": "success",
                "status_code": 200,
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

        data = {
            "ip": ip,
        }
        if provider:
            data["provider"] = provider
        if verbose:
            data["verbose"] = verbose
        if raw:
            data["raw"] = raw

        return self.request.post("lookup", data=data)


class UrlIntel(ServiceBase):
    """URL Intel service client.

    Provides methods to interact with [Pangea URL Intel Service](/docs/api/url-intel)

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)
        URL_INTEL_CONFIG_ID - Configuration ID which can be found on the Pangea
            User Console at [https://console.pangea.cloud/service/url-intel](https://console.pangea.cloud/service/url-intel)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import UrlIntel

        PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")
        URL_INTEL_CONFIG_ID = os.getenv("URL_INTEL_CONFIG_ID")

        url_intel_config = PangeaConfig(domain="pangea.cloud",
                                        config_id=URL_INTEL_CONFIG_ID)

        # Setup Pangea URL Intel service
        url_intel = UrlIntel(token=PANGEA_TOKEN, config=url_intel_config)
    """

    service_name = "url-intel"
    version = "v1"

    def lookup(self, url: str, provider: str = None, verbose: bool = False, raw: bool = False) -> PangeaResponse:
        """
        Retrieve URL address reputation from a provider.

        Args:
            url (str): URL address to be looked up
            provider (str, optional): Provider of the reputation information. ("crowdstrike"). Default provider defined by the configuration.
            verbose (bool, optional): Echo back the parameters of the API in the response
            raw (bool, optional): Return additional details from the provider.

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/url-intel)

        Examples:
            response = url_intel.lookup("http://113.235.101.11:54384", provider="crowdstrike")

            \"\"\"
            response contains:
            {
                "request_id": "prq_5ugxruda7vmsgioup6vjvaqmnmvxzbqv",
                "request_time": "2022-08-23T03:40:03.549Z",
                "response_time": "2022-08-23T03:40:03.694Z",
                "status": "success",
                "status_code": 200,
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

        data = {
            "url": url,
        }
        if provider:
            data["provider"] = provider
        if verbose:
            data["verbose"] = verbose
        if raw:
            data["raw"] = raw

        return self.request.post("lookup", data=data)


class DomainIntel(ServiceBase):
    """Domain Intel service client

    Provides methods to interact with [Pangea Domain Intel Service](/docs/api/domain-intel)

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)
        DOMAIN - Configuration ID which can be found on the Pangea
            User Console at [https://console.pangea.cloud/service/domain-intel](https://console.pangea.cloud/service/domain-intel)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import DomainIntel

        PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")
        DOMAIN = os.getenv("DOMAIN_INTEL_CONFIG_ID")

        domain_intel_config = PangeaConfig(domain="pangea.cloud",
                                        config_id=DOMAIN_INTEL_CONFIG_ID)

        # Setup Pangea Domain Intel service
        domain_intel = DomainIntel(token=PANGEA_TOKEN, config=domain_intel_config)
    """

    service_name = "domain-intel"
    version = "v1"

    def lookup(self, domain: str, provider: str = None, verbose: bool = False, raw: bool = False) -> PangeaResponse:
        """
        Retrieve Domain reputation from a provider.

        Args:
            domain (str): Domain address to be looked up
            provider (str, optional): Provider of the reputation information. ("crowdstrike"). Default provider defined by the configuration.
            verbose (bool, optional): Echo back the parameters of the API in the response
            raw (bool, optional): Return additional details from the provider.

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/domain-intel)

        Examples:
            response = domain_intel.lookup("teoghehofuuxo.su", provider="crowdstrike")

            \"\"\"
            response contains:
            \"\"\"
        """

        data = {
            "domain": domain,
        }
        if provider:
            data["provider"] = provider
        if verbose:
            data["verbose"] = verbose
        if raw:
            data["raw"] = raw

        return self.request.post("lookup", data=data)

# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from fileinput import FileInput
from typing import Dict, List, Optional

from pydantic import BaseModel

from pangea.response import PangeaResponse, PangeaResponseResult

from .base import ServiceBase


class BaseModelConfig(BaseModel):
    class Config:
        arbitrary_types_allowed = True


class FileLookupInput(BaseModelConfig):
    """
    TODO: complete

    file_hash (str): Hash of the file to be looked up
    hash_type (str): Type of hash, can be "sha256", "sha" or "md5"
    provider (str, optional): Provider of the reputation information. ("reversinglabs" or "crowdstrike"). Default provider defined by the configuration.
    verbose (bool, optional): Echo back the parameters of the API in the response
    raw (bool, optional): Return additional details from the provider.
    """

    hash: str
    hash_type: str
    verbose: Optional[bool] = None
    raw: Optional[bool] = None
    provider: Optional[str] = None


class FileLookupData(BaseModelConfig):
    """
    TODO: complete
    """

    category: List[str]
    score: int
    verdict: str


class FileLookupOutput(PangeaResponseResult):
    """
    TODO: complete
    """

    data: FileLookupData
    parameters: Optional[Dict] = None
    raw_data: Optional[Dict] = None


class IPLookupInput(BaseModelConfig):
    """
    TODO: complete

    ip (str): IP address to be looked up
    provider (str, optional): Provider of the reputation information. ("crowdstrike"). Default provider defined by the configuration.
    verbose (bool, optional): Echo back the parameters of the API in the response
    raw (bool, optional): Return additional details from the provider.
    """

    ip: str
    verbose: Optional[bool] = None
    raw: Optional[bool] = None
    provider: Optional[str] = None


class IPLookupData(BaseModelConfig):
    """
    TODO: complete
    """

    category: List[str]
    score: int
    verdict: str


class IPLookupOutput(PangeaResponseResult):
    """
    TODO: complete
    """

    data: IPLookupData
    parameters: Optional[Dict] = None
    raw_data: Optional[Dict] = None


class DomainLookupInput(BaseModelConfig):
    """
    TODO: complete

    domain (str): Domain address to be looked up
    provider (str, optional): Provider of the reputation information. ("crowdstrike"). Default provider defined by the configuration.
    verbose (bool, optional): Echo back the parameters of the API in the response
    raw (bool, optional): Return additional details from the provider.
    """

    domain: str
    verbose: Optional[bool] = None
    raw: Optional[bool] = None
    provider: Optional[str] = None


class DomainLookupData(BaseModelConfig):
    """
    TODO: complete
    """

    category: List[str]
    score: int
    verdict: str


class DomainLookupOutput(PangeaResponseResult):
    """
    TODO: complete
    """

    data: DomainLookupData
    parameters: Optional[Dict] = None
    raw_data: Optional[Dict] = None


class URLLookupInput(BaseModelConfig):
    """
    TODO: complete

    url (str): URL address to be looked up
    provider (str, optional): Provider of the reputation information. ("crowdstrike"). Default provider defined by the configuration.
    verbose (bool, optional): Echo back the parameters of the API in the response
    raw (bool, optional): Return additional details from the provider.
    """

    url: str
    verbose: Optional[bool] = None
    raw: Optional[bool] = None
    provider: Optional[str] = None


class URLLookupData(BaseModelConfig):
    """
    TODO: complete
    """

    category: List[str]
    score: int
    verdict: str


class URLLookupOutput(PangeaResponseResult):
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

    def lookup(self, input=FileLookupInput) -> PangeaResponse[FileLookupOutput]:
        """
        Lookup file reputation by hash.

        Retrieve file reputation from a provider, using the file's hash.

        Args:
            input (FileLookupInput): input with file information to perform request

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/file-intel).

        Examples:
            response = file_intel.lookup(FileLookupInput(hash="322ccbd42b7e4fd3a9d0167ca2fa9f6483d9691364c431625f1df54270647ca8", hash_type="sha256", provider="crowdstrike"))

            \"\"\"
            response contains:
            {
                "request_id": "prq_shfq6vhj7xvi6b6noswfkuoeaxtzgpnb",
                "request_time": "2022-08-23T02:43:17.614Z",
                "response_time": "2022-08-23T02:43:18.607Z",
                "status": "success",
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

        response = self.request.post("lookup", data=input.dict(exclude_none=True))
        response.result = FileLookupOutput(**response.result)
        return response


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

    def lookup(self, input: IPLookupInput) -> PangeaResponse[IPLookupOutput]:
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

        response = self.request.post("lookup", data=input.dict(exclude_none=True))
        response.result = IPLookupOutput(**response.result)
        return response


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

    def lookup(self, input: URLLookupInput) -> PangeaResponse[URLLookupOutput]:
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

        response = self.request.post("lookup", data=input.dict(exclude_none=True))
        response.result = URLLookupOutput(**response.raw_result)
        return response


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

    def lookup(self, input: DomainLookupInput) -> PangeaResponse[DomainLookupOutput]:
        """
        Retrieve Domain reputation from a provider.

        Args:
            input (URLLookupInput): input with domain information to perform request

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/domain-intel)

        Examples:
            response = domain_intel.lookup(DomainLookupInput(domain"teoghehofuuxo.su", provider="crowdstrike"))

            \"\"\"
            response contains:
            \"\"\"
        """

        response = self.request.post("lookup", data=input.dict(exclude_none=True))
        response.result = DomainLookupOutput(**response.raw_result)
        return response

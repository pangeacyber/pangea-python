# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from pangea.response import PangeaResponse

from .base import ServiceBase


class FileIntel(ServiceBase):
    """File Intel service client.

    Provides methods to interact with Pangea File Intel Service:
        https://docs.pangea.cloud/docs/api/file-intel

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)
        File FILE_INTEL_CONFIG_ID - Configuration ID which can be found on the Pangea
            User Console at [https://console.pangea.cloud/service/File Intel](https://console.pangea.cloud/service/file-intel)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import FileIntel

        PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")
        FILE_INTEL_CONFIG_ID = os.getenv("FILE_INTEL_CONFIG_ID")

        file_intel_config = PangeaConfig(base_domain="pangea.cloud",
                                        config_id=FILE_INTEL_CONFIG_ID)

        # Setup Pangea File Intel service
        file_intel = FileIntel(token=PANGEA_TOKEN, config=file_intel_config)
    """

    service_name = "file-intel"
    version = "v1"

    def lookup(self, file_hash: str, hash_type: str, provider: str = None, verbose: bool = False, raw: bool = False) -> PangeaResponse:
        """
        Lookup file reputation by hash.

        Retrieve file reputation from a provider, using the file's hash.

        Args:
            file_hash (str): Hash of the file to be looked up
            hash_type (str): Type of hash, can be "sha256", "sha" or "md5"
            provider (str, optional): Provider of the reputation information. ("reversinglabs" or "crowdstrike"). Default provider defined by the configuration.
            verbose (bool, optional): Echo back the parameters of the API in the response
            raw (bool, optional): Return additional details from the provider.

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found
                at: [https://docs.pangea.cloud/docs/api/file-intel](https://docs.pangea.cloud/docs/api/file-intel)

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
            "parameters": {
                "hash": file_hash,
                "hash_type": hash_type,
            }
        }
        if provider:
            data["provider"] = provider
        if verbose:
            data["parameters"]["verbose"] = verbose
        if raw:
            data["parameters"]["raw"] = raw

        return self.request.post("lookup", data=data)


# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from pangea.response import PangeaResponse

from .base import ServiceBase


class Embargo(ServiceBase):
    """Embargo service client.

    Provides methods to interact with Pangea Embargo Service:
        https://docs.dev.pangea.cloud/docs/api/embargo

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.dev.pangea.cloud/project/tokens]
            (https://console.dev.pangea.cloud/project/tokens)
        EMBARGO_CONFIG_ID - Configuration ID which can be found on the Pangea
            User Console at [https://console.dev.pangea.cloud/service/embargo]
            (https://console.dev.pangea.cloud/service/embargo)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import Embargo

        PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")
        EMBARGO_CONFIG_ID = os.getenv("EMBARGO_CONFIG_ID")

        embargo_config = PangeaConfig(base_domain="dev.pangea.cloud",
                                        config_id=EMBARGO_CONFIG_ID)

        # Setup Pangea Embargo service
        embargo = Embargo(token=PANGEA_TOKEN, config=embargo_config)
    """

    service_name = "embargo"
    version = "v1"

    def check_ip(self, ip: str) -> PangeaResponse:
        """
        Embargo

        Check this IP against known sanction and trade embargo lists.

        Args:
            ip (str): Geolocate this IP and check the corresponding country
                against the enabled embargo lists.  Accepts both IPV4 and IPV6 strings.

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found
                at: [https://docs.dev.pangea.cloud/docs/api/embargo]
                (https://docs.dev.pangea.cloud/docs/api/embargo)

        Examples:
            response = embargo.check_ip("1.1.1.1")

            \"\"\"
            response contains:
            {
                "request_id": "prq_lws4ldnnruaos2a4c2ohgw7ijodzqf52",
                "request_time": "2022-07-06T23:37:36.952Z",
                "response_time": "2022-07-06T23:37:37.104Z",
                "status": "success",
                "status_code": 200,
                "summary": "Found country in 1 embargo list(s)",
                "result": {
                    "sanctions": [
                    {
                        "list_name": "ITAR",
                        "embargoed_country_name": "North Korea/Democratic Peoples Republic of Korea",
                        "embargoed_country_iso_code": "KP",
                        "issuing_country": "US",
                        "annotations": {
                        "reference": {
                            "paragraph": "d1",
                            "regulation": "CFR 126.1"
                        },
                        "restriction_name": "ITAR"
                        }
                    }
                    ],
                    "count": 1
                }
            }
            \"\"\"
        """

        return self.request.post("check", data={"ip": ip})

    def check_isocode(self, iso_code: str) -> PangeaResponse:
        """
        Embargo

        Check this country against known sanction and trade embargo lists.

        Args:
            iso_code (str): Check this two character country ISO-code against
                the enabled embargo lists.

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found
                at: [https://docs.dev.pangea.cloud/docs/api/embargo]
                (https://docs.dev.pangea.cloud/docs/api/embargo)

        Examples:
            response = embargo.check_isocode("FR")

            \"\"\"
            response contains:
            {
                "request_id": "prq_fa6yqoztkfdyg655s6dut5e3bn3plmj5",
                "request_time": "2022-07-06T23:44:29.248Z",
                "response_time": "2022-07-06T23:44:29.357Z",
                "status": "success",
                "status_code": 200,
                "summary": "Found country in 0 embargo list(s)",
                "result": {
                    "sanctions": null,
                    "count": 0
                }
            }
            \"\"\"
        """

        return self.request.post("check", data={"iso_code": iso_code})

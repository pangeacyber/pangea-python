# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from typing import Any, Dict, List

from pangea.response import APIRequestModel, APIResponseModel, PangeaResponse, PangeaResponseResult

from .base import ServiceBase


class IPCheckRequest(APIRequestModel):
    """
    Input class to perform a IP check request

    Arguments:
    IP -- IP to check against the enabled embargo lists. Accepts both IPV4 and IPV6 strings.
    """

    ip: str


class ISOCheckRequest(APIRequestModel):
    """
    Input class to perform a ISO check

    Arguments:
    ISOCode -- Check this two character country ISO-code against the enabled embargo lists.
    """

    iso_code: str


class Sanction(APIResponseModel):
    """
    TODO: complete
    """

    embargoed_country_iso_code: str
    issuing_country: str
    list_name: str
    embargoed_country_name: str
    annotations: Dict[str, Any]


class EmbargoResult(PangeaResponseResult):
    """
    Class returned after check request

    TODO: complete
    """

    count: int
    sanctions: List[Sanction]


class Embargo(ServiceBase):
    """Embargo service client.

    Provides methods to interact with Pangea Embargo Service:
        https://pangea.cloud/docs/api/embargo

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import Embargo

        PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")

        embargo_config = PangeaConfig(domain="aws.us.pangea.cloud")

        # Setup Pangea Embargo service
        embargo = Embargo(token=PANGEA_TOKEN, config=embargo_config)
    """

    service_name = "embargo"
    version = "v1"

    def ip_check(self, ip: str) -> PangeaResponse[EmbargoResult]:
        """
        Check IP

        Check this IP against known sanction and trade embargo lists.

        Args:
            ip (str): Geolocate this IP and check the corresponding country
                against the enabled embargo lists.  Accepts both IPV4 and IPV6 strings.

        Raises:
            EmbargoException: If an embargo based api exception happens
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found
                in our [API Documentation](https://pangea.cloud/docs/api/embargo).

        Examples:
            response = embargo.ip_check("1.1.1.1")

            \"\"\"
            response contains:
            {
                "request_id": "prq_lws4ldnnruaos2a4c2ohgw7ijodzqf52",
                "request_time": "2022-07-06T23:37:36.952Z",
                "response_time": "2022-07-06T23:37:37.104Z",
                "status": "success",
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
        input = IPCheckRequest(ip=ip)
        response = self.request.post("ip/check", data=input.dict())
        result = EmbargoResult(**response.raw_result)
        response.result = result
        return response

    def iso_check(self, iso_code: str) -> PangeaResponse[EmbargoResult]:
        """
        ISO Code Check

        Check this country against known sanction and trade embargo lists.

        Args:
            iso_code (str): Check this two character country ISO-code against
                the enabled embargo lists.

        Raises:
            EmbargoException: If an embargo based api exception happens
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found
                in our [API Documentation](https://pangea.cloud/docs/api/embargo).

        Examples:
            response = embargo.lookup("FR")

            \"\"\"
            response contains:
            {
                "request_id": "prq_fa6yqoztkfdyg655s6dut5e3bn3plmj5",
                "request_time": "2022-07-06T23:44:29.248Z",
                "response_time": "2022-07-06T23:44:29.357Z",
                "status": "success",
                "summary": "Found country in 0 embargo list(s)",
                "result": {
                    "sanctions": null,
                    "count": 0
                }
            }
            \"\"\"
        """
        input = ISOCheckRequest(iso_code=iso_code)
        response = self.request.post("iso/check", data=input.dict())
        response.result = EmbargoResult(**response.raw_result)
        return response

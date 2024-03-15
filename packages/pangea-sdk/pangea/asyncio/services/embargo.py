# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import pangea.services.embargo as e
from pangea.asyncio.services.base import ServiceBaseAsync
from pangea.response import PangeaResponse


class EmbargoAsync(ServiceBaseAsync):
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

    async def ip_check(self, ip: str) -> PangeaResponse[e.EmbargoResult]:
        """
        Check IP

        Check an IP against known sanction and trade embargo lists.

        OperationId: embargo_post_v1_ip_check

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
            response = embargo.ip_check("190.6.64.94")
        """
        input = e.IPCheckRequest(ip=ip)
        return await self.request.post("v1/ip/check", e.EmbargoResult, data=input.model_dump())

    async def iso_check(self, iso_code: str) -> PangeaResponse[e.EmbargoResult]:
        """
        ISO Code Check

        Check this country against known sanction and trade embargo lists.

        OperationId: embargo_post_v1_iso_check

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
            response = embargo.iso_check("CU")
        """
        input = e.ISOCheckRequest(iso_code=iso_code)
        return await self.request.post("v1/iso/check", result_class=e.EmbargoResult, data=input.model_dump())

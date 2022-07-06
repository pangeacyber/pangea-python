# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from pangea.response import PangeaResponse

from .base import ServiceBase


class Embargo(ServiceBase):
    """
    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import Embargo

        PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")
        EMBARGO_CONFIG_ID = os.getenv("EMBARGO_CONFIG_ID")

        embargo_config = PangeaConfig(base_domain="dev.pangea.cloud", config_id=EMBARGO_CONFIG_ID)

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
            ip (str): Geolocate this IP and check the corresponding country against the enabled embargo lists.
            Accepts both IPV4 and IPV6 strings.

        Returns:
            A PangeaResponse.

        Examples:
            response = embargo.check_ip("1.1.1.1")
        """

        return self.request.post("check", data={"ip": ip})

    def check_isocode(self, iso_code: str) -> PangeaResponse:
        """
        Embargo

        Check this country against known sanction and trade embargo lists.

        Args:
            iso_code (str): Check this two character country ISO-code against the enabled embargo lists.

        Returns:
            A PangeaResponse.

        Examples:
            response = embargo.check_isocode("FR")
        """

        return self.request.post("check", data={"iso_code": iso_code})

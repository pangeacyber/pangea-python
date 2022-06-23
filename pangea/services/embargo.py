# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from pangea.response import PangeaResponse
from .base import ServiceBase


class Embargo(ServiceBase):
    service_name = "embargo"
    version = "v1"

    def check_ip(self, ip: str) -> PangeaResponse:
        """
        Embargo

        Check IPs and country codes against known sanction and trade embargo lists.

        Args:
            ip (ipv4 or ipv6 str): Geolocate this IP and check the corresponding country against the enabled embargo lists. Note: Either the IP or ISO_CODE parameter must be provided, not both.

        Returns:
            A PangeaResponse.
        """

        return self.request.post("check", data={"ip": ip})

    def check_isocode(self, iso_code: str) -> PangeaResponse:
        """
        Embargo

        Check IPs and country codes against known sanction and trade embargo lists.

        Args:
            iso_code (str): Check this two character country ISO code against the enabled embargo lists. Note: Either the IP or ISO_CODE parameter must be provided, not both.

        Returns:
            A PangeaResponse.
        """

        return self.request.post("check", data={"iso_code": iso_code})

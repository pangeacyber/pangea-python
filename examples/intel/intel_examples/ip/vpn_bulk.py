# Determine if an IP address originates from a VPN.

import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import IpIntel

from intel_examples.ip.utils import print_ip_vpn_bulk_data

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
url_template = os.getenv("PANGEA_URL_TEMPLATE")
assert url_template
config = PangeaConfig(base_url_template=url_template)
intel = IpIntel(token, config=config)


def main():
    print("Checking IP's a VPN...")

    try:
        response = intel.is_vpn_bulk(
            ips=["2.56.189.74", "24.235.114.61"], provider="digitalelement", verbose=True, raw=True
        )
        print("Result:")
        print_ip_vpn_bulk_data(response.result.data)

    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        print(e)


if __name__ == "__main__":
    main()

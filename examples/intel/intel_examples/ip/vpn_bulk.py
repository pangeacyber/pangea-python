import os

import pangea.exceptions as pe
from intel_examples.ip.utils import print_ip_vpn_bulk_data
from pangea.config import PangeaConfig
from pangea.services import IpIntel

token = os.getenv("PANGEA_INTEL_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
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

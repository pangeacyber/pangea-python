# Determine if an IP address is provided by a VPN service.

import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import IpIntel

from intel_examples.ip.utils import print_ip_vpn_data

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
intel = IpIntel(token, config=config)


def main():
    print("Checking if the IP belongs to a VPN service...")

    try:
        ip = "2.56.189.74"
        response = intel.is_vpn(ip="2.56.189.74", provider="digitalelement", verbose=True, raw=True)
        print("Result:")
        print_ip_vpn_data(ip, response.result.data)

    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        print(e)


if __name__ == "__main__":
    main()

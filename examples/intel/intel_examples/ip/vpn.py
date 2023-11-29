import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import IpIntel

token = os.getenv("PANGEA_INTEL_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
intel = IpIntel(token, config=config)


def main():
    print("Checking if the IP belongs to a VPN service...")

    try:
        response = intel.is_vpn(ip="2.56.189.74", provider="digitalelement", verbose=True, raw=True)
        if response.result.data.is_vpn:
            print("IP is a VPN")
        else:
            print("IP is not a VPN")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        print(e)


if __name__ == "__main__":
    main()

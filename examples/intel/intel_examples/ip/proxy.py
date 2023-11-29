import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import IpIntel

token = os.getenv("PANGEA_INTEL_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
intel = IpIntel(token, config=config)


def main():
    print("Checking if an IP belongs to a proxy service...")

    try:
        response = intel.is_proxy(ip="34.201.32.172", provider="digitalelement", verbose=True, raw=True)
        if response.result.data.is_proxy:
            print("IP is a proxy")
        else:
            print("IP is not a proxy")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        print(e)


if __name__ == "__main__":
    main()

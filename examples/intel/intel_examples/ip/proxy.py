import os

import pangea.exceptions as pe
from intel_examples.ip.utils import print_ip_proxy_data
from pangea.config import PangeaConfig
from pangea.services import IpIntel

token = os.getenv("PANGEA_INTEL_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
intel = IpIntel(token, config=config)


def main():
    print("Checking IP's proxy...")

    try:
        ip = "34.201.32.172"
        response = intel.is_proxy(ip=ip, provider="digitalelement", verbose=True, raw=True)
        print("Result:")
        print_ip_proxy_data(ip, response.result.data)
    except pe.PangeaAPIException as e:
        print(e)


if __name__ == "__main__":
    main()

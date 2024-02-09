import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import IpIntel

from intel_examples.ip.utils import print_ip_proxy_bulk_data

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
intel = IpIntel(token, config=config)


def main():
    print("Checking IP's proxy...")

    try:
        response = intel.is_proxy_bulk(
            ips=["34.201.32.172", "2.56.189.74"], provider="digitalelement", verbose=True, raw=True
        )
        print("Result:")
        print_ip_proxy_bulk_data(response.result.data)
    except pe.PangeaAPIException as e:
        print(e)


if __name__ == "__main__":
    main()

import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import IpIntel

from intel_examples.utils import print_reputation_bulk_data

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
intel = IpIntel(token, config=config)


def main():
    print("Checking IPs...")

    try:
        ip_list = ["93.231.182.110", "190.28.74.251"]
        response = intel.reputation_bulk(ips=ip_list, provider="crowdstrike", verbose=True, raw=True)
        print("Result:")
        print_reputation_bulk_data(response.result.data)
    except pe.PangeaAPIException as e:
        print(e)


if __name__ == "__main__":
    main()

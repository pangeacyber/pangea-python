# Retrieve the domain names associated with a list of IP addresses.

import os

from pangea.config import PangeaConfig
from pangea.services import IpIntel

from intel_examples.ip.utils import print_ip_domain_bulk_data

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
intel = IpIntel(token, config=config)


def main() -> None:
    print("Get IP's Domain...")
    response = intel.get_domain_bulk(
        ips=["24.235.114.61", "93.231.182.110"], provider="digitalelement", verbose=True, raw=True
    )
    assert response.result
    print_ip_domain_bulk_data(response.result.data)


if __name__ == "__main__":
    main()

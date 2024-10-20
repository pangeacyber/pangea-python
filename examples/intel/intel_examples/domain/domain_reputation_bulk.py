# Retrieve reputation for multiple domains.

import os

from pangea.config import PangeaConfig
from pangea.services import DomainIntel

from intel_examples.utils import print_reputation_bulk_data

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
intel = DomainIntel(token, config=config)


def main() -> None:
    print("Checking domains...")
    domain_list = ["pemewizubidob.cafij.co.za", "redbomb.com.tr", "kmbk8.hicp.net"]
    response = intel.reputation_bulk(domains=domain_list, provider="crowdstrike", verbose=True, raw=True)
    assert response.result
    print("Result:")
    print_reputation_bulk_data(response.result.data)


if __name__ == "__main__":
    main()

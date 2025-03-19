# Retrieve a reputation score for an IP address.
# This score will fall under one of these categories: benign, suspicious,
# malicious, or unknown.

import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import IpIntel

from intel_examples.utils import print_reputation_bulk_data

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
url_template = os.getenv("PANGEA_URL_TEMPLATE")
assert url_template
config = PangeaConfig(base_url_template=url_template)
intel = IpIntel(token, config=config)


def main() -> None:
    print("Checking IPs...")
    ip_list = ["93.231.182.110", "190.28.74.251"]
    response = intel.reputation_bulk(ips=ip_list, provider="crowdstrike", verbose=True, raw=True)
    assert response.result
    print("Result:")
    print_reputation_bulk_data(response.result.data)


if __name__ == "__main__":
    main()

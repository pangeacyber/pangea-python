# Retrieve a reputation score for an IP address.
# This score will fall under one of these categories: benign, suspicious,
# malicious, or unknown.

from __future__ import annotations

import os
import sys
from pathlib import Path

from pangea.config import PangeaConfig
from pangea.services import IpIntel

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from intel_examples.utils import print_reputation_bulk_data

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
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

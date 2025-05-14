# Retrieve a reputation score for an IP address from the "cymru" provider.
# This score will fall under one of these categories: benign, suspicious,
# malicious, or unknown.

from __future__ import annotations

import os

from pangea.config import PangeaConfig
from pangea.services import IpIntel

from intel_examples.utils import print_reputation_data

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
intel = IpIntel(token, config=config)


def main() -> None:
    print("Checking IP...")
    indicator = "93.231.182.110"
    response = intel.reputation(ip=indicator, provider="cymru", verbose=True, raw=True)
    assert response.result
    print("Result:")
    print_reputation_data(indicator, response.result.data)


if __name__ == "__main__":
    main()

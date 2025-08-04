# Retrieve a reputation score for a URL.
# This score will fall under one of these categories: benign, suspicious,
# malicious, or unknown.

import os
import sys
from pathlib import Path

from pangea.config import PangeaConfig
from pangea.services import UrlIntel

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from intel_examples.utils import print_reputation_data

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
intel = UrlIntel(token, config=config)


def main() -> None:
    print("Checking URL...")
    indicator = "http://113.235.101.11:54384"
    response = intel.reputation(url=indicator, provider="crowdstrike", verbose=True, raw=True)
    assert response.result
    print("Result:")
    print_reputation_data(indicator, response.result.data)


if __name__ == "__main__":
    main()

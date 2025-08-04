# Use Pangea's Domain Intel service to retrieve reputation for a domain.

import os
import sys
from pathlib import Path

from pangea.config import PangeaConfig
from pangea.services import DomainIntel

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from intel_examples.utils import print_reputation_data

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
intel = DomainIntel(token, config=config)


def main() -> None:
    print("Checking domain...")
    indicator = "737updatesboeing.com"
    response = intel.reputation(domain=indicator, provider="domaintools", verbose=True, raw=True)
    assert response.result
    print("Result:")
    print_reputation_data(indicator, response.result.data)


if __name__ == "__main__":
    main()

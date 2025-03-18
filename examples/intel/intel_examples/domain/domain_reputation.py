# Use Pangea's Domain Intel service to retrieve reputation for a domain.

import os

from pangea.config import PangeaConfig
from pangea.services import DomainIntel

from intel_examples.utils import print_reputation_data

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
url_template = os.getenv("PANGEA_URL_TEMPLATE")
assert url_template
config = PangeaConfig(base_url_template=url_template)
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

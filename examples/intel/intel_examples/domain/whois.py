import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import DomainIntel

token = os.getenv("PANGEA_INTEL_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
intel = DomainIntel(token, config=config)


def main():
    print("Looking up whois data for domain...")

    try:
        response = intel.who_is(domain="737updatesboeing.com", provider="whoisxml", verbose=True, raw=True)
        print(f"Response: {response.result}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

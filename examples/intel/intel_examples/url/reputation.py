import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import UrlIntel

token = os.getenv("PANGEA_INTEL_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
intel = UrlIntel(token, config=config)


def main():
    print(f"Checking URL...")

    try:
        response = intel.reputation(url="http://113.235.101.11:54384", provider="crowdstrike", verbose=True, raw=True)
        print(f"Response: {response.result}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

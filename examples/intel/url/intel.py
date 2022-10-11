import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import UrlIntel

token = os.getenv("INTEL_AUTH_TOKEN")
config_id = os.getenv("INTEL_URL_CONFIG_ID")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain, config_id=config_id)
intel = UrlIntel(token, config=config)


def main():
    print(f"Checking URL...")

    try:
        response = intel.lookup(url="http://113.235.101.11:54384", provider="domaintools", verbose=True, raw=True)
        print(f"Response: {response.result}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

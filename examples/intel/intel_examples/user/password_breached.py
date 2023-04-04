import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import UserIntel
from pangea.services.intel import HashType

token = os.getenv("PANGEA_INTEL_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
intel = UserIntel(token, config=config)


def main():
    print(f"Checking password breached...")

    try:
        response = intel.password_breached(
            hash_prefix="5baa6", hash_type=HashType.SHA256, provider="spycloud", verbose=True, raw=True
        )
        print(f"Response: {response.result}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

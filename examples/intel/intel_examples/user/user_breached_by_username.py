import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import UserIntel

token = os.getenv("PANGEA_INTEL_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
intel = UserIntel(token, config=config)


def main():
    print("Checking user by username...")

    try:
        response = intel.user_breached(username="shortpatrick", provider="spycloud", verbose=True, raw=True)
        print(f"Found in breach: {response.result.data.found_in_breach}")
        print(f"Breach count: {response.result.data.breach_count}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

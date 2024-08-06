# Check a country against known sanction and trade embargo lists.

import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import Embargo

token = os.getenv("PANGEA_EMBARGO_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
embargo = Embargo(token, config=config)


def main() -> None:
    # Country code to check.
    country_code = "CU"
    print(f"Checking Embargo ISO code: {country_code}")

    try:
        # Check the country code against known sanction and trade embargo lists.
        embargo_response = embargo.iso_check(iso_code=country_code)
        print(f"Response: {embargo_response.result}")
    except pe.PangeaAPIException as e:
        print(f"Embargo Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import Embargo

token = os.getenv("PANGEA_EMBARGO_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
embargo = Embargo(token, config=config)


def main():
    country_code = "CU"
    print(f"Checking Embargo ISO code: {country_code}")

    try:
        embargo_response = embargo.iso_check(iso_code=country_code)
        print(f"Response: {embargo_response.result}")
    except pe.PangeaAPIException as e:
        print(f"Embargo Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

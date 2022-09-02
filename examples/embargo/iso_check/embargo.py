import os

from pangea.config import PangeaConfig
from pangea.services import Embargo

token = os.getenv("EMBARGO_AUTH_TOKEN")
config_id = os.getenv("EMBARGO_CONFIG_ID")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain, config_id=config_id)
embargo = Embargo(token, config=config)


def main():
    country_code = "CU"
    print(f"Checking Embargo ISO code: {country_code}")
    embargo_response = embargo.iso_check(country_code)

    if embargo_response.success:
        print(f"Response: {embargo_response.result}")
    else:
        print(f"Embargo Request Error: {embargo_response.response.text}")
        if embargo_response.result and embargo_response.result.errors:
            for err in embargo_response.result.errors:
                print(f"\t{err.detail}")
            print("")


if __name__ == "__main__":
    main()

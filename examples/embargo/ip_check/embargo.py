import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import Embargo

token = os.getenv("EMBARGO_AUTH_TOKEN")
config_id = os.getenv("EMBARGO_CONFIG_ID")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain, config_id=config_id)
embargo = Embargo(token, config=config)


def main():
    ip = "213.24.238.26"
    print(f"Checking Embargo IP: {ip}")
    try:
        embargo_response = embargo.ip_check(ip=ip)
        print(f"Response: {embargo_response.result}")
    except pe.PangeaAPIException as e:
        print(f"Embargo Request Error: {e.response.summary}")
        if e.errors:
            for err in e.errors:
                print(f"\t{err.detail}")
            print("")


if __name__ == "__main__":
    main()

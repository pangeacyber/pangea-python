import os

import pangea.exceptions as pe
from intel_examples.utils import print_reputation_bulk_data
from pangea.config import PangeaConfig
from pangea.services import UrlIntel

token = os.getenv("PANGEA_INTEL_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
intel = UrlIntel(token, config=config)


def main():
    print("Checking URL...")

    try:
        url_list = [
            "http://113.235.101.11:54384",
            "http://45.14.49.109:54819",
            "https://chcial.ru/uplcv?utm_term%3Dcost%2Bto%2Brezone%2Bland",
        ]
        response = intel.reputation_bulk(urls=url_list, provider="crowdstrike", verbose=True, raw=True)
        print("Result:")
        print_reputation_bulk_data(response.result.data)
    except pe.PangeaAPIException as e:
        print(e)


if __name__ == "__main__":
    main()

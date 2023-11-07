import os

import pangea.exceptions as pe
from intel_examples.utils import print_reputation_data
from pangea.config import PangeaConfig
from pangea.services import IpIntel

token = os.getenv("PANGEA_INTEL_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
intel = IpIntel(token, config=config)


def main():
    print("Checking IP...")

    try:
        indicator = "93.231.182.110"
        response = intel.reputation(ip=indicator, provider="crowdstrike", verbose=True, raw=True)
        print("Result:")
        print_reputation_data(indicator, response.result.data)
    except pe.PangeaAPIException as e:
        print(e)


if __name__ == "__main__":
    main()

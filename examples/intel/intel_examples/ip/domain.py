import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import IpIntel

token = os.getenv("PANGEA_INTEL_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
intel = IpIntel(token, config=config)


def main():
    print("Get IP's Domain...")

    try:
        response = intel.get_domain(ip="24.235.114.61", provider="digitalelement", verbose=True, raw=True)
        print(f"IP's domain was {'' if response.result.data.domain_found is True else 'not '}found")
        if response.result.data.domain_found:
            print(f"IP's domain is: {response.result.data.domain}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        print(e)


if __name__ == "__main__":
    main()

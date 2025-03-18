# Determine if an IP address originates from a proxy.

import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import IpIntel

from intel_examples.ip.utils import print_ip_proxy_data

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
url_template = os.getenv("PANGEA_URL_TEMPLATE")
assert url_template
config = PangeaConfig(base_url_template=url_template)
intel = IpIntel(token, config=config)


def main():
    print("Checking if an IP belongs to a proxy service...")
    ip = "34.201.32.172"
    response = intel.is_proxy(ip=ip, provider="digitalelement", verbose=True, raw=True)
    print("Result:")
    print_ip_proxy_data(ip, response.result.data)


if __name__ == "__main__":
    main()

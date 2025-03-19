# Retrieve the domain name associated with an IP address.

import os

from pangea.config import PangeaConfig
from pangea.services import IpIntel

from intel_examples.ip.utils import print_ip_domain_data

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
url_template = os.getenv("PANGEA_URL_TEMPLATE")
assert url_template
config = PangeaConfig(base_url_template=url_template)
intel = IpIntel(token, config=config)


def main() -> None:
    print("Get IP's Domain...")
    ip = "24.235.114.61"
    response = intel.get_domain(ip=ip, provider="digitalelement", verbose=True, raw=True)
    assert response.result
    print_ip_domain_data(ip, response.result.data)


if __name__ == "__main__":
    main()

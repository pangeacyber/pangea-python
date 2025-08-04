# Retrieve the domain name associated with an IP address.

import os
import sys
from pathlib import Path

from pangea.config import PangeaConfig
from pangea.services import IpIntel

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from intel_examples.ip.utils import print_ip_domain_data

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
intel = IpIntel(token, config=config)


def main() -> None:
    print("Get IP's Domain...")
    ip = "24.235.114.61"
    response = intel.get_domain(ip=ip, provider="digitalelement", verbose=True, raw=True)
    assert response.result
    print_ip_domain_data(ip, response.result.data)


if __name__ == "__main__":
    main()

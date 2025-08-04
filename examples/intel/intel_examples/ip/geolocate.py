# Retrieve location information associated with an IP address.

import os
import sys
from pathlib import Path

from pangea.config import PangeaConfig
from pangea.services import IpIntel

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from intel_examples.ip.utils import print_ip_geolocate_data

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
intel = IpIntel(token, config=config)


def main() -> None:
    print("Geolocate IP...")
    ip = "93.231.182.110"
    response = intel.geolocate(ip=ip, provider="digitalelement", verbose=True, raw=True)
    assert response.result
    print("Result")
    print_ip_geolocate_data(ip, response.result.data)


if __name__ == "__main__":
    main()

# Retrieve location information associated with an IP address.

import os

from pangea.config import PangeaConfig
from pangea.services import IpIntel

from intel_examples.ip.utils import print_ip_geolocate_data

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
url_template = os.getenv("PANGEA_URL_TEMPLATE")
assert url_template
config = PangeaConfig(base_url_template=url_template)
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

# Determine if an IP address is provided by a VPN service.

import asyncio
import os

import pangea.exceptions as pe
from pangea.asyncio.services import IpIntelAsync
from pangea.config import PangeaConfig

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
url_template = os.getenv("PANGEA_URL_TEMPLATE")
assert url_template
config = PangeaConfig(base_url_template=url_template)
intel = IpIntelAsync(token, config=config)


async def main():
    print("Checking IP's a VPN...")

    try:
        response = await intel.is_vpn(ip="2.56.189.74", provider="digitalelement", verbose=True, raw=True)
        if response.result.data.is_vpn:
            print("IP is a VPN")
        else:
            print("IP is not a VPN")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        print(e)

    await intel.close()


if __name__ == "__main__":
    asyncio.run(main())

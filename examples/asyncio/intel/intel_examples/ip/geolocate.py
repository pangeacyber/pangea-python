# Retrieve information about the location of an IP address.

import asyncio
import os

from pangea.asyncio.services import IpIntelAsync
from pangea.config import PangeaConfig

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
intel = IpIntelAsync(token, config=config)


async def main() -> None:
    print("Geolocate IP...")
    response = await intel.geolocate(ip="93.231.182.110", provider="digitalelement", verbose=True, raw=True)
    print(f"Response: {response.result}")
    await intel.close()


if __name__ == "__main__":
    asyncio.run(main())

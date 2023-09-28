import asyncio
import os

import pangea.exceptions as pe
from pangea.asyncio.services import IpIntelAsync
from pangea.config import PangeaConfig

token = os.getenv("PANGEA_INTEL_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
intel = IpIntelAsync(token, config=config)


async def main():
    print("Geolocate IP...")

    try:
        response = await intel.geolocate(ip="93.231.182.110", provider="digitalelement", verbose=True, raw=True)
        print(f"Response: {response.result}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        print(e)

    await intel.close()


if __name__ == "__main__":
    asyncio.run(main())

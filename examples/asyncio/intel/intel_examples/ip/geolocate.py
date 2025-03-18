# Retrieve information about the location of an IP address.

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


async def main() -> None:
    print("Geolocate IP...")

    try:
        response = await intel.geolocate(ip="93.231.182.110", provider="digitalelement", verbose=True, raw=True)
        print(f"Response: {response.result}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        print(e)
    finally:
        await intel.close()


if __name__ == "__main__":
    asyncio.run(main())

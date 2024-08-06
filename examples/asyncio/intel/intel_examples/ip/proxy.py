# Determine if an IP address originates from a proxy.

import asyncio
import os

import pangea.exceptions as pe
from pangea.asyncio.services import IpIntelAsync
from pangea.config import PangeaConfig

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
intel = IpIntelAsync(token, config=config)


async def main():
    print("Checking IP's proxy...")

    try:
        response = await intel.is_proxy(ip="34.201.32.172", provider="digitalelement", verbose=True, raw=True)
        if response.result.data.is_proxy:
            print("IP is a proxy")
        else:
            print("IP is not a proxy")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        print(e)

    await intel.close()


if __name__ == "__main__":
    asyncio.run(main())

# Use Pangea's IP Intel service to retrieve a reputation score for an IP address
# via the "crowdstrike" provider. This score will fall under one of these
# categories: benign, suspicious, malicious, or unknown.

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


async def main() -> None:
    print("Checking IP...")

    try:
        response = await intel.reputation(ip="93.231.182.110", provider="crowdstrike", verbose=True, raw=True)
        print(f"Response: {response.result}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")
    finally:
        await intel.close()


if __name__ == "__main__":
    asyncio.run(main())

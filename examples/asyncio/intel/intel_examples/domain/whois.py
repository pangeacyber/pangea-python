import asyncio
import os

import pangea.exceptions as pe
from pangea.asyncio.services import DomainIntelAsync
from pangea.config import PangeaConfig

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
intel = DomainIntelAsync(token, config=config)


async def main():
    print("Checking domain...")

    try:
        response = await intel.who_is(domain="737updatesboeing.com", provider="whoisxml", verbose=True, raw=True)
        print(f"Response: {response.result}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")

    await intel.close()


if __name__ == "__main__":
    asyncio.run(main())

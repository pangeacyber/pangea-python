# Look up breached users.
#
# Determine if a username was exposed in a security breach.

import asyncio
import os

import pangea.exceptions as pe
from pangea.asyncio.services import UserIntelAsync
from pangea.config import PangeaConfig

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
intel = UserIntelAsync(token, config=config)


async def main():
    print("Checking user by username...")

    try:
        response = await intel.user_breached(username="shortpatrick", provider="spycloud", verbose=True, raw=True)
        print(f"Found in breach: {response.result.data.found_in_breach}")
        print(f"Breach count: {response.result.data.breach_count}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")

    await intel.close()


if __name__ == "__main__":
    asyncio.run(main())

# Look up breached users.
#
# Determine if an IP address was exposed in a security breach.

import asyncio
import os

import pangea.exceptions as pe
from pangea.asyncio.services import UserIntelAsync
from pangea.config import PangeaConfig

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
url_template = os.getenv("PANGEA_URL_TEMPLATE")
assert url_template
config = PangeaConfig(base_url_template=url_template)
intel = UserIntelAsync(token, config=config)


async def main():
    print("Checking user by IP...")

    try:
        response = await intel.user_breached(ip="192.168.140.37", provider="spycloud", verbose=True, raw=True)
        print(f"Found in breach: {response.result.data.found_in_breach}")
        print(f"Breach count: {response.result.data.breach_count}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")

    await intel.close()


if __name__ == "__main__":
    asyncio.run(main())

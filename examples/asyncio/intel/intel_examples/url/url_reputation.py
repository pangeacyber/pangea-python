# Retrieve URL address reputation from a provider.

import asyncio
import os

import pangea.exceptions as pe
from pangea.asyncio.services import UrlIntelAsync
from pangea.config import PangeaConfig

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
url_template = os.getenv("PANGEA_URL_TEMPLATE")
assert url_template
config = PangeaConfig(base_url_template=url_template)
intel = UrlIntelAsync(token, config=config)


async def main() -> None:
    print("Checking URL...")

    try:
        response = await intel.reputation(
            url="http://113.235.101.11:54384", provider="crowdstrike", verbose=True, raw=True
        )
        print(f"Response: {response.result}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")
    finally:
        await intel.close()


if __name__ == "__main__":
    asyncio.run(main())

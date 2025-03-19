# Check a country against known sanction and trade embargo lists.

import asyncio
import os

import pangea.exceptions as pe
from pangea.asyncio.services import EmbargoAsync
from pangea.config import PangeaConfig

token = os.getenv("PANGEA_EMBARGO_TOKEN")
assert token
url_template = os.getenv("PANGEA_URL_TEMPLATE")
assert url_template
config = PangeaConfig(base_url_template=url_template)
embargo = EmbargoAsync(token, config=config)


async def main():
    country_code = "CU"
    print(f"Checking Embargo ISO code: {country_code}")

    try:
        embargo_response = await embargo.iso_check(iso_code=country_code)
        print(f"Response: {embargo_response.result}")
    except pe.PangeaAPIException as e:
        print(f"Embargo Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")

    await embargo.close()


if __name__ == "__main__":
    asyncio.run(main())

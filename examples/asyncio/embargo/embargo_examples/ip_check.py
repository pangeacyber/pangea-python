import asyncio
import os

import pangea.exceptions as pe
from pangea.asyncio.services import EmbargoAsync
from pangea.config import PangeaConfig
from pangea.tools import logger_set_pangea_config

token = os.getenv("PANGEA_EMBARGO_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
embargo = EmbargoAsync(token, config=config, logger_name="embargo")
logger_set_pangea_config(logger_name=embargo.logger.name)


async def main():
    ip = "213.24.238.26"
    print(f"Checking Embargo IP: {ip}")
    try:
        embargo_response = await embargo.ip_check(ip=ip)
        print(f"Response: {embargo_response.result}")
    except pe.PangeaAPIException as e:
        print(f"Embargo Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")

    await embargo.close()


if __name__ == "__main__":
    asyncio.run(main())

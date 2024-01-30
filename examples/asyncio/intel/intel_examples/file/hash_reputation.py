import asyncio
import os

import pangea.exceptions as pe
from pangea.asyncio.services import FileIntelAsync
from pangea.config import PangeaConfig
from pangea.tools import logger_set_pangea_config

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
intel = FileIntelAsync(token, config=config, logger_name="intel")
logger_set_pangea_config(logger_name=intel.logger.name)


async def main():
    print("Checking hash...")

    try:
        response = await intel.hash_reputation(
            hash="142b638c6a60b60c7f9928da4fb85a5a8e1422a9ffdc9ee49e17e56ccca9cf6e",
            hash_type="sha256",
            provider="reversinglabs",
            verbose=True,
            raw=True,
        )
        print(f"Response: {response.result}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")

    await intel.close()


if __name__ == "__main__":
    asyncio.run(main())

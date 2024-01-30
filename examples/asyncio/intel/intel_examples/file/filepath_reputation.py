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
    print("Checking file...")

    try:
        response = await intel.filepath_reputation(
            filepath="./pyproject.toml",
            provider="reversinglabs",
            verbose=True,
            raw=True,
        )
        print(f"Response: {response.result}")
    except pe.PangeaAPIException as e:
        print(e)

    await intel.close()


if __name__ == "__main__":
    asyncio.run(main())

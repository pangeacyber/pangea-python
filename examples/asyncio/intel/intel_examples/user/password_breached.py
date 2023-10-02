import asyncio
import os

import pangea.exceptions as pe
from pangea.asyncio.services import UserIntelAsync
from pangea.config import PangeaConfig
from pangea.services import UserIntel
from pangea.services.intel import HashType
from pangea.tools import logger_set_pangea_config
from pangea.utils import get_prefix, hash_sha256

token = os.getenv("PANGEA_INTEL_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
intel = UserIntelAsync(token, config=config, logger_name="intel")
logger_set_pangea_config(logger_name=intel.logger.name)


async def main():
    print("Checking password breached...")
    # Set the password you would like to check
    password = "mypassword"
    # Calculate its hash, it could be sha256 or sha1
    hash = hash_sha256(password)
    # get the hash prefix, right know it should be just 5 characters
    hash_prefix = get_prefix(hash)

    try:
        response = await intel.password_breached(
            # should setup right hash_type here, sha256 or sha1
            hash_prefix=hash_prefix,
            hash_type=HashType.SHA256,
            provider="spycloud",
            verbose=True,
            raw=True,
        )

        # This auxiliary function analyze service provider raw data to search for full hash in their registers
        status = UserIntel.is_password_breached(response, hash)
        if status == UserIntel.PasswordStatus.BREACHED:
            print(f"Password: '{password}' has been breached")
        elif status == UserIntel.PasswordStatus.UNBREACHED:
            print(f"Password: '{password}' has not been breached")
        elif status == UserIntel.PasswordStatus.INCONCLUSIVE:
            print(f"Not enough information to confirm if password '{password}' has been or has not been breached.")
        else:
            print(f"Unknown status: {status}")

    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")

    await intel.close()


if __name__ == "__main__":
    asyncio.run(main())

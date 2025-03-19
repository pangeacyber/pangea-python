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
assert token
url_template = os.getenv("PANGEA_URL_TEMPLATE")
assert url_template
config = PangeaConfig(base_url_template=url_template)
intel = UserIntelAsync(token, config=config, logger_name="intel")
logger_set_pangea_config(logger_name=intel.logger.name)


async def main():
    print("Checking password breached...")
    # Set the password you would like to check
    password = "mypassword"
    # Calculate its hash, current options are sha256, sha1, sha512, and ntlm.
    hash = hash_sha256(password)
    # Get the hash prefix, the first 5 characters of the hash.
    hash_prefix = get_prefix(hash)

    try:
        response = await intel.password_breached(
            # Set the correct hash_type here, sha256, sha1, sha512, and ntlm.
            hash_prefix=hash_prefix,
            hash_type=HashType.SHA256,
            provider="spycloud",
            verbose=True,
            raw=True,
        )

        # This auxiliary function analyzes the service provider's raw data to search for the full hash in their registers.
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

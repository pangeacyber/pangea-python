# This example shows how to perform an audit log.

import asyncio
import os

import pangea.exceptions as pe
from pangea.asyncio.services import AuditAsync
from pangea.config import PangeaConfig
from pangea.tools import logger_set_pangea_config

token = os.getenv("PANGEA_AUDIT_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
audit = AuditAsync(token, config=config, logger_name="audit")
logger_set_pangea_config(logger_name=audit.logger.name)


async def main() -> None:
    # Message to log.
    msg = "Hello, World!"
    print(f"Logging: {msg}")

    try:
        # Log the message to Pangea Secure Audit Log.
        log_response = await audit.log(message=msg, verbose=True)
        assert log_response.result
        print(f"Envelope: {log_response.result.envelope}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")
    finally:
        await audit.close()


if __name__ == "__main__":
    asyncio.run(main())

import asyncio
import os
import time

import pangea.exceptions as pe
from pangea.asyncio.services import AuditAsync
from pangea.config import PangeaConfig
from pangea.services.audit.models import Event
from pangea.tools import logger_set_pangea_config

token = os.getenv("PANGEA_AUDIT_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
audit = AuditAsync(token, config=config, logger_name="audit")
logger_set_pangea_config(logger_name=audit.logger.name)

# This example shows how to perform an audit log


async def main():
    print("Logging bulk...")

    event1 = Event(
        message="Sign up",
        actor="pangea-sdk",
    )

    event2 = Event(
        message="Sign in",
        actor="pangea-sdk",
    )

    start = time.time()
    await audit.log_bulk_async(events=[event1, event2], verbose=True)
    end = time.time()

    print(f"Sent 2 events in {int((end - start)*1000)} miliseconds")
    await audit.close()


if __name__ == "__main__":
    asyncio.run(main())

import os
import time

from pangea.config import PangeaConfig
from pangea.services import Audit
from pangea.services.audit.models import Event
from pangea.tools import logger_set_pangea_config

token = os.getenv("PANGEA_AUDIT_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
audit = Audit(token, config=config, logger_name="audit")
logger_set_pangea_config(logger_name=audit.logger.name)

# This example shows how to perform an audit log


def main():
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
    audit.log_bulk_async(events=[event1, event2], verbose=True)
    end = time.time()

    print(f"Sent 2 events in {int((end - start)*1000)} milliseconds")


if __name__ == "__main__":
    main()

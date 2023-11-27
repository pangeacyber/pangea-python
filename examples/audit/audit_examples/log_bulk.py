import os
import time

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import Audit
from pangea.services.audit.models import Event
from pangea.tools import logger_set_pangea_config

token = os.getenv("PANGEA_AUDIT_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
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

    try:
        start = time.time()
        log_response = audit.log_bulk(events=[event1, event2], verbose=True)
        end = time.time()

        print(f"log 2 events in {int((end - start)*1000)} miliseconds")

        for result in log_response.result.results:
            print(f"Envelope: {result.envelope}")

    except pe.PangeaAPIException as e:
        print(e)


if __name__ == "__main__":
    main()

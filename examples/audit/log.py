import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import Audit
from pangea.services.audit.models import Event

token = os.getenv("PANGEA_AUDIT_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
audit = Audit(token, config=config)

# This example shows how to perform an audit log


def main():
    msg = "Hello, World!"
    print(f"Logging: {msg}")

    try:
        log_response = audit.log(message=msg, verbose=False)
        print(f"Response: {log_response.result}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

import json
import os

from pangea.config import PangeaConfig
from pangea.exceptions import AuditException
from pangea.services import Audit
from pangea.services.audit import Event

token = os.getenv("AUDIT_AUTH_TOKEN")
config_id = os.getenv("AUDIT_CONFIG_ID")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain, config_id=config_id)
audit = Audit(token, config=config)


def main():
    event = Event(
        message="Hello world",
        actor="Someone",
        action="Testing",
        source="My computer",
        status="Good",
        target="Another spot",
        new="New updated message",
        old="Old message that it's been updated",
    )

    print(f"Logging: {event.dict(exclude_none=True)}")

    try:
        log_response = audit.log(event=event, verbose=False)
        print(f"Response: {log_response.result.dict(exclude_none=True)}")
    except AuditException as e:
        print(f"Log Request Error: {e.message}")


if __name__ == "__main__":
    main()

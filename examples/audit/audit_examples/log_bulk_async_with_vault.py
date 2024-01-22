import os

from pangea.config import PangeaConfig
from pangea.services import Audit, Vault
from pangea.services.audit.models import Event
from pangea.tools import logger_set_pangea_config

vault_token = os.getenv("PANGEA_VAULT_TOKEN")
audit_token_vault_id = os.getenv("PANGEA_AUDIT_TOKEN_VAULT_ID")
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
logger_set_pangea_config(logger_name="audit")

# This example shows how to perform an audit log


def main():
    print("Logging bulk...")
    vault = Vault(vault_token, config=config, logger_name="vault")
    vault_response = vault.get(audit_token_vault_id)
    audit_token = vault_response.result.current_version.secret
    # You may want to use a different audit config object.
    audit = Audit(audit_token, config=config, logger_name="audit")

    event1 = Event(
        message="Sign up",
        actor="pangea-sdk",
    )

    audit.log_bulk_async(events=[event1], verbose=False)

    print("Sent event")


if __name__ == "__main__":
    main()

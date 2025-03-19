from __future__ import annotations

import os

from pangea.config import PangeaConfig
from pangea.services import Audit, Vault
from pangea.services.audit.models import Event
from pangea.tools import logger_set_pangea_config

# Vault API token.
vault_token = os.getenv("PANGEA_VAULT_TOKEN")
assert vault_token

# Vault ID of the Secure Audit Log token.
audit_token_vault_id = os.getenv("PANGEA_AUDIT_TOKEN_VAULT_ID")
assert audit_token_vault_id

# Pangea domain.
url_template = os.getenv("PANGEA_URL_TEMPLATE")
assert url_template

config = PangeaConfig(base_url_template=url_template)
logger_set_pangea_config(logger_name="audit")


def main():
    print("Logging bulk...")

    # Create a Vault API client and fetch the previously-stored Secure Audit Log
    # token.
    vault = Vault(vault_token, config=config, logger_name="vault")
    vault_response = vault.get_bulk({"id": audit_token_vault_id})
    audit_token = vault_response.result.items[0].item_versions[0].token

    # Use that token to create a new Secure Audit Log API client and log a
    # message.
    audit = Audit(audit_token, config=config, logger_name="audit")

    event1 = Event(
        message="Sign up",
        actor="pangea-sdk",
    )

    audit.log_bulk_async(events=[event1], verbose=False)

    print("Sent event")


if __name__ == "__main__":
    main()

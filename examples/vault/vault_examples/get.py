import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import Audit, Vault


def main() -> None:
    token = os.getenv("PANGEA_VAULT_TOKEN")
    domain = os.getenv("PANGEA_DOMAIN")
    assert domain
    config = PangeaConfig(domain=domain)
    vault = Vault(token, config=config)

    try:
        # ID of the audit token
        token_id = os.getenv("PANGEA_AUDIT_TOKEN_ID")
        assert token_id

        # Fetch the audit token.
        create_response = vault.get(id=token_id)
        assert create_response.result
        assert create_response.result.current_version
        audit_token = create_response.result.current_version.secret

        msg = "Hello, World!"
        audit = Audit(audit_token, config=config, logger_name="audit")
        log_response = audit.log(message=msg, verbose=True)
        assert log_response.result
        print(f"Envelope: {log_response.result.envelope}")

    except pe.PangeaAPIException as e:
        print(f"Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

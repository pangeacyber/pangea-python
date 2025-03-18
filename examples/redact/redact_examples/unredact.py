# Redact sensitive information from provided text.

import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import Redact
from pangea.services.redact import VaultParameters
from pangea.tools import logger_set_pangea_config

token = os.getenv("PANGEA_REDACT_TOKEN")
assert token
url_template = os.getenv("PANGEA_URL_TEMPLATE")
assert url_template
key_id = os.getenv("PANGEA_VAULT_FPE_KEY_ID")
assert key_id

config = PangeaConfig(base_url_template=url_template)
redact = Redact(token, config=config)
logger_set_pangea_config(logger_name=redact.logger.name)


def main() -> None:
    # Text to be redacted.
    text = "Visit our web is https://pangea.cloud"
    print(f"Redacting PII from: {text}")

    try:
        # Redact sensitive information from the text.
        redact_response = redact.redact(text=text, vault_parameters=VaultParameters(fpe_key_id=key_id))
        assert redact_response.result
        assert redact_response.result.redacted_text
        assert redact_response.result.fpe_context
        print(f"Redacted text: {redact_response.result.redacted_text}")

        unredact_response = redact.unredact(
            redacted_data=redact_response.result.redacted_text, fpe_context=redact_response.result.fpe_context
        )
        assert unredact_response.result
        print(f"Unredacted text: {unredact_response.result.data}")

    except pe.PangeaAPIException as e:
        print(f"Redact Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

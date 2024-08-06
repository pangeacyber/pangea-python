# Redact sensitive information from provided text.

import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import Redact

token = os.getenv("PANGEA_REDACT_MULTICONFIG_TOKEN")
assert token
config_id = os.getenv("PANGEA_REDACT_CONFIG_ID")
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)

# Set config_id in service constructor
redact = Redact(token, config=config, config_id=config_id)


def main() -> None:
    # Text to be redacted.
    text = "Hello, my phone number is 123-456-7890"
    print(f"Redacting PII from: {text}")

    try:
        # Redact sensitive information from the text.
        redact_response = redact.redact(text=text)
        assert redact_response.result
        print(f"Redacted text: {redact_response.result.redacted_text}")
    except pe.PangeaAPIException as e:
        print(f"Redact Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

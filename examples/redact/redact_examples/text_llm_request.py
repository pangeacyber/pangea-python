# Redact sensitive information from provided text.

import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import Redact

token = os.getenv("PANGEA_REDACT_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
redact = Redact(token, config=config)


def main() -> None:
    # Text to be redacted.
    text = "Visit our web is https://pangea.cloud"
    print(f"Redacting PII from: {text}")

    try:
        # Redact sensitive information from the text.
        redact_response = redact.redact(text=text, llm_request=True)
        assert redact_response.result
        assert redact_response.result.redacted_text
        print(f"Redacted text: {redact_response.result.redacted_text}")

        fpe_context = redact_response.result.fpe_context
        assert fpe_context

        # Unredact the response
        unredacted_response = redact.unredact(redact_response.result.redacted_text, fpe_context)
        assert unredacted_response.result
        print(f"Unredacted response: {unredacted_response.result.data}")

    except pe.PangeaAPIException as e:
        print(f"Redact Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

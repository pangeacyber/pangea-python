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


def main():
    text = "Hello, my phone number is 123-456-7890"
    print(f"Redacting PII from: {text}")

    try:
        redact_response = redact.redact(text=text)
        print(f"Redacted text: {redact_response.result.redacted_text}")
    except pe.PangeaAPIException as e:
        print(f"Embargo Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import Redact

token = os.getenv("REDACT_AUTH_TOKEN")
config_id = os.getenv("REDACT_CONFIG_ID")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain, config_id=config_id)
redact = Redact(token, config=config)


def main():
    text = "Hello, my phone number is 123-456-7890"
    print(f"Redacting PII from: {text}")

    try:
        redact_response = redact.redact(text=text)
        print(f"Response: {redact_response.result}")
    except pe.PangeaAPIException as e:
        print(f"Embargo Request Error: {e.response.summary}")
        if e.errors:
            for err in e.errors:
                print(f"\t{err.detail}")
            print("")


if __name__ == "__main__":
    main()

import os

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
    redact_response = redact.redact(text)

    if redact_response.success:
        print(f"Response: {redact_response.result}")
    else:
        print(f"Embargo Request Error: {redact_response.response.text}")
        if redact_response.result and redact_response.result.errors:
            for err in redact_response.result.errors:
                print(f"\t{err.detail}")
            print("")


if __name__ == "__main__":
    main()

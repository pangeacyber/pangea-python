# Redact sensitive information from provided text.

import json
import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import Redact

token = os.getenv("PANGEA_REDACT_TOKEN")
assert token
url_template = os.getenv("PANGEA_URL_TEMPLATE")
assert url_template
config = PangeaConfig(base_url_template=url_template)
redact = Redact(token, config=config)


def main() -> None:
    # data to be redacted.
    data = {
        "phone": "415-867-5309",
        "name": "Jenny Jenny",
    }

    print(f"Redacting PII from: {json.dumps(data)}")

    try:
        # Redact sensitive information from the test.
        redact_response = redact.redact_structured(data=data)
        assert redact_response.result
        print(f"Redacted data: {json.dumps(redact_response.result.redacted_data)}")
    except pe.PangeaAPIException as e:
        print(f"Redact Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

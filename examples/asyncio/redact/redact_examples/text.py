import asyncio
import os

import pangea.exceptions as pe
from pangea.asyncio.services import RedactAsync
from pangea.config import PangeaConfig

token = os.getenv("PANGEA_REDACT_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
redact = RedactAsync(token, config=config)


async def main():
    text = "Hello, my phone number is 123-456-7890"
    print(f"Redacting PII from: {text}")

    try:
        redact_response = await redact.redact(text=text)
        print(f"Redacted text: {redact_response.result.redacted_text}")
    except pe.PangeaAPIException as e:
        print(f"Embargo Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")

    await redact.close()


if __name__ == "__main__":
    asyncio.run(main())

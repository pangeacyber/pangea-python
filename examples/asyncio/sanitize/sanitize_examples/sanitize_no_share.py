import asyncio
import os
import sys

import pangea.exceptions as pe
from pangea.asyncio.services import SanitizeAsync
from pangea.config import PangeaConfig
from pangea.response import TransferMethod
from pangea.services.sanitize import SanitizeContent, SanitizeFile, SanitizeShareOutput

# Set this filepath to your own file
FILEPATH = "./sanitize_examples/test-sanitize.txt"


async def main() -> None:
    token = os.getenv("PANGEA_SANITIZE_TOKEN")
    assert token

    domain = os.getenv("PANGEA_DOMAIN")
    assert domain

    config = PangeaConfig(domain=domain)

    # Create Sanitize client with its token and its config
    client = SanitizeAsync(token, config)
    try:
        # Create Sanitize file information
        file_scan = SanitizeFile(scan_provider="crowdstrike")

        # Create content sanitization config
        content = SanitizeContent(
            url_intel=True,
            url_intel_provider="crowdstrike",
            domain_intel=True,
            domain_intel_provider="crowdstrike",
            defang=True,
            defang_threshold=20,
            redact=True,
        )
        # Disable share output
        share_output = SanitizeShareOutput(enabled=False)

        with open(FILEPATH, "rb") as f:
            # Make the request to sanitize service
            response = await client.sanitize(
                file=f,
                transfer_method=TransferMethod.POST_URL,
                file_scan=file_scan,
                content=content,
                share_output=share_output,
                uploaded_file_name="uploaded_file",
            )

            print("Sanitize request success")
            if response.result is None:
                print("Failed to get response")
                sys.exit(1)

            print(f"\tRedact data: {response.result.data.redact}")
            print(f"\tDefang data: {response.result.data.defang}")

            if response.result.data.malicious_file:
                print("File IS malicious")
            else:
                print("File is NOT malicious")

            if response.result.dest_url is None:
                print("Failed to get dest url")
                sys.exit(1)

            url = response.result.dest_url
            print(f"\tDownload URL: {url}")

            # Download file
            print("Downloading file...")
            attached_file = await client.download_file(url)

            # Saving file
            print("Saving file...")
            attached_file.save("./")

            print("Saving success.")
    except pe.PangeaAPIException as e:
        print(e)

    await client.close()


if __name__ == "__main__":
    asyncio.run(main())

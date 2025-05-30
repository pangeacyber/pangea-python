import os
import sys

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.response import TransferMethod
from pangea.services import Sanitize
from pangea.services.sanitize import SanitizeContent, SanitizeFile, SanitizeShareOutput

# Set this filepath to your own file
FILEPATH = "./sanitize_examples/test-sanitize.txt"


def main() -> None:
    token = os.getenv("PANGEA_SANITIZE_TOKEN")
    assert token

    domain = os.getenv("PANGEA_DOMAIN")
    assert domain

    config = PangeaConfig(domain=domain)

    # Create Sanitize client with its token and its config
    client = Sanitize(token, config)
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
        # Enable share output and its folder
        share_output = SanitizeShareOutput(enabled=True, output_folder="sdk_examples/sanitize/")

        with open(FILEPATH, "rb") as f:
            # Make the request to sanitize service
            response = client.sanitize(
                file=f,
                # Set transfer method to multipart
                transfer_method=TransferMethod.MULTIPART,
                file_scan=file_scan,
                content=content,
                share_output=share_output,
                uploaded_file_name="uploaded_file",
            )

            if response.result is None:
                print("Failed to get response")
                sys.exit(1)

            print("Sanitize request success")
            print(f"\tFile share id: {response.result.dest_share_id}")
            print(f"\tRedact data: {response.result.data.redact}")
            print(f"\tDefang data: {response.result.data.defang}")

            if response.result.data.malicious_file:
                print("File IS malicious")
            else:
                print("File is NOT malicious")

    except pe.PangeaAPIException as e:
        print(e)


if __name__ == "__main__":
    main()

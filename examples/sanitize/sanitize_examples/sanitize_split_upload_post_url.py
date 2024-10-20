import os
import sys
import time

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.file_uploader import FileUploader
from pangea.response import PangeaResponse, TransferMethod
from pangea.services import Sanitize
from pangea.services.sanitize import (
    SanitizeContent,
    SanitizeFile,
    SanitizeResult,
    SanitizeShareOutput,
)
from pangea.utils import get_file_upload_params

# Set this filepath to your own file
FILEPATH = "./sanitize_examples/ds11.pdf"


def main() -> None:
    token = os.getenv("PANGEA_SANITIZE_TOKEN")
    assert token

    domain = os.getenv("PANGEA_DOMAIN")
    assert domain

    config = PangeaConfig(domain)
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
            remove_interactive=True,
            remove_attachments=True,
            redact=True,
        )
        # Enable share output and its folder
        share_output = SanitizeShareOutput(enabled=True, output_folder="sdk_examples/sanitize/")

        with open(FILEPATH, "rb") as f:
            params = get_file_upload_params(f)
            response_url = client.request_upload_url(
                # Set transfer method to post-url
                transfer_method=TransferMethod.POST_URL,
                file_scan=file_scan,
                content=content,
                share_output=share_output,
                params=params,
                uploaded_file_name="uploaded_file",
            )

            # Get post url to upload the file and its form data
            if response_url.accepted_result is None or response_url.accepted_result.post_url is None:
                print("Failed to get post url")
                sys.exit(1)

            url = response_url.accepted_result.post_url
            file_details = response_url.accepted_result.post_form_data
            print(f"\nGot presigned url: {url}")

            uploader = FileUploader()
            # Upload file. Set transfer method to post-url
            uploader.upload_file(url=url, file=f, transfer_method=TransferMethod.POST_URL, file_details=file_details)
            print("Upload file success")

        max_retry = 12
        print("Let's try to poll sanitize result...")
        for retry in range(max_retry):
            try:
                # wait some time to get result ready and poll it
                time.sleep(10)
                response: PangeaResponse[SanitizeResult] = client.poll_result(response=response_url)

                if response.result is None:
                    print("Failed to get response")
                    sys.exit(1)

                print("Poll result success")
                print(f"\tFile share id: {response.result.dest_share_id}")
                print(f"\tRedact data: {response.result.data.redact}")
                print(f"\tDefang data: {response.result.data.defang}")
                print(f"\tCDR data: {response.result.data.cdr}")

                if response.result.data.malicious_file:
                    print("File IS malicious")
                else:
                    print("File is NOT malicious")
                break

            except pe.AcceptedRequestException:
                print(f"Result is not ready yet. Retry: {retry}")

    except pe.PangeaAPIException as e:
        print(e)


if __name__ == "__main__":
    main()

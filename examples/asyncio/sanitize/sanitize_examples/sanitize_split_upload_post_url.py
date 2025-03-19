import asyncio
import os
import sys

import pangea.exceptions as pe
from pangea.asyncio.file_uploader import FileUploaderAsync
from pangea.asyncio.services import SanitizeAsync
from pangea.config import PangeaConfig
from pangea.response import PangeaResponse, TransferMethod
from pangea.services.sanitize import (
    SanitizeContent,
    SanitizeFile,
    SanitizeResult,
    SanitizeShareOutput,
)
from pangea.utils import get_file_upload_params

# Set this filepath to your own file
FILEPATH = "./sanitize_examples/test-sanitize.txt"


async def main() -> None:
    token = os.getenv("PANGEA_SANITIZE_TOKEN")
    assert token

    url_template = os.getenv("PANGEA_URL_TEMPLATE")
    assert url_template

    config = PangeaConfig(url_template)
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
        # Enable share output and its folder
        share_output = SanitizeShareOutput(enabled=True, output_folder="sdk_examples/sanitize/")

        with open(FILEPATH, "rb") as f:
            params = get_file_upload_params(f)
            response_url = await client.request_upload_url(
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

            uploader = FileUploaderAsync()
            # Upload file. Set transfer method to post-url
            await uploader.upload_file(
                url=url, file=f, transfer_method=TransferMethod.POST_URL, file_details=file_details
            )
            print("Upload file success")

        max_retry = 12
        print("Let's try to poll sanitize result...")
        for retry in range(max_retry):
            try:
                # wait some time to get result ready and poll it
                await asyncio.sleep(10)
                response: PangeaResponse[SanitizeResult] = await client.poll_result(response=response_url)

                if response.result is None:
                    print("Failed to get response")
                    sys.exit(1)

                print("Poll result success")
                print(f"\tFile share id: {response.result.dest_share_id}")
                print(f"\tRedact data: {response.result.data.redact}")
                print(f"\tDefang data: {response.result.data.defang}")

                if response.result.data.malicious_file:
                    print("File IS malicious")
                else:
                    print("File is NOT malicious")
                break

            except pe.AcceptedRequestException:
                print(f"Result is not ready yet. Retry: {retry}")

    except pe.PangeaAPIException as e:
        print(e)

    await client.close()
    await uploader.close()


if __name__ == "__main__":
    asyncio.run(main())

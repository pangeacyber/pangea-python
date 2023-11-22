import os
import time

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.response import PangeaResponse, TransferMethod
from pangea.services import FileScan
from pangea.services.file_scan import FileScanResult, FileUploader
from pangea.tools import logger_set_pangea_config
from pangea.utils import get_file_upload_params

token = os.getenv("PANGEA_FILE_SCAN_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
# To work in sync it's need to set up queue_retry_enable to true and set up a proper timeout
# If timeout it's so little service won't end up and will return an AcceptedRequestException anyway
config = PangeaConfig(domain=domain, queued_retry_enabled=True, poll_result_timeout=120)
client = FileScan(token, config=config, logger_name="pangea")
logger_set_pangea_config(logger_name=client.logger.name)

FILEPATH = "./file_scan_examples/testfile.pdf"


def main():
    print("Checking file...")

    try:
        with open(FILEPATH, "rb") as f:
            # get file params needed to request upload url
            params = get_file_upload_params(f)

            # request an upload url
            response = client.request_upload_url(
                transfer_method=TransferMethod.POST_URL, params=params, verbose=True, provider="reversinglabs"
            )

            # extract upload url and upload details that should be posted with the file
            url = response.accepted_result.accepted_status.upload_url
            file_details = response.accepted_result.accepted_status.upload_details

            print(f"Got presigned url: {url}")

            # Create an uploader and upload the file
            uploader = FileUploader()
            uploader.upload_file(url=url, file=f, transfer_method=TransferMethod.POST_URL, file_details=file_details)
            print("Upload file success")

        max_retry = 24
        print("Let's try to poll scan result...")
        for retry in range(max_retry):
            try:
                # wait some time to get result ready and poll it
                time.sleep(10)

                # Try to poll result. If it's not ready, it will raise an AcceptedRequestException
                response: PangeaResponse[FileScanResult] = client.poll_result(response=response)
                print("Got result successfully...")
                print(f"Response: {response.result}")
                break
            except pe.AcceptedRequestException:
                print(f"Result is not ready yet. Retry: {retry}")

    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

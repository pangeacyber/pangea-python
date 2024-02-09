import datetime
import os
import time

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.response import PangeaResponse, TransferMethod
from pangea.services import Store
from pangea.services.store.store import FileUploader, PutResult
from pangea.utils import get_file_upload_params

token = os.getenv("PANGEA_STORE_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)

# Create a path name
date = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
filepath = "./store_examples/testfile.pdf"

# Create service object
store = Store(token, config=config)


def main():
    try:
        print("Uploading file with multipart method...")
        name = f"{date}_file_split_post_url"
        with open(filepath, "rb") as f:
            params = get_file_upload_params(f)
            print("Requesting upload url...")
            response = store.request_upload_url(
                name=name,
                transfer_method=TransferMethod.POST_URL,
                crc32c=params.crc_hex,
                sha256=params.sha256_hex,
                size=params.size,
            )
            url = response.accepted_result.post_url
            file_details = response.accepted_result.post_form_data

            print("Request URL success. Uploading file...")
            uploader = FileUploader()
            uploader.upload_file(
                url=url,
                name=name,
                file=f,
                transfer_method=TransferMethod.POST_URL,
                file_details=file_details,
            )

            print("Upload file success.")

        max_retry = 24
        for retry in range(max_retry):
            try:
                # wait some time to get result ready and poll it
                print(f"Polling result. Retry: {retry}.")
                time.sleep(10)
                response: PangeaResponse[PutResult] = store.poll_result(response=response)

                print(f"Poll result success. Item ID: {response.result.object.id}")
                break
            except pe.AcceptedRequestException:
                print("Result is not ready yet.")
                if retry >= max_retry:
                    print("Error: reached max retry.")
                    break
    except pe.PangeaAPIException as e:
        print(f"Store request error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

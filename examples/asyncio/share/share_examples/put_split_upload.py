import asyncio
import datetime
import os
import time

import pangea.exceptions as pe
from pangea.asyncio import FileUploaderAsync
from pangea.asyncio.services import ShareAsync
from pangea.config import PangeaConfig
from pangea.response import PangeaResponse, TransferMethod
from pangea.services.share.share import PutResult  # type: ignore
from pangea.utils import get_file_upload_params

token = os.getenv("PANGEA_SHARE_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)

# Create a path name
date = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
filepath = "./share_examples/testfile.pdf"

# Create service object
share = ShareAsync(token, config=config)


async def main():
    try:
        print("Uploading file with multipart method...")
        name = f"{date}_file_split_post_url"
        with open(filepath, "rb") as f:
            params = get_file_upload_params(f)
            print("Requesting upload url...")
            response = await share.request_upload_url(
                name=name,
                transfer_method=TransferMethod.POST_URL,
                crc32c=params.crc_hex,
                sha256=params.sha256_hex,
                size=params.size,
            )
            url = response.accepted_result.post_url
            file_details = response.accepted_result.post_form_data

            print("Request URL success. Uploading file...")
            uploader = FileUploaderAsync()
            await uploader.upload_file(
                url=url,
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
                response: PangeaResponse[PutResult] = await share.poll_result(response=response)

                print(f"Poll result success. Item ID: {response.result.object.id}")
                break
            except pe.AcceptedRequestException:
                print("Result is not ready yet.")
                if retry >= max_retry:
                    print("Error: reached max retry.")
                    break
        await share.close()
        await uploader.close()
    except pe.PangeaAPIException as e:
        print(f"Share request error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    asyncio.run(main())

import asyncio
import datetime
import os

import pangea.exceptions as pe
from pangea.asyncio.services import ShareAsync
from pangea.config import PangeaConfig
from pangea.response import TransferMethod

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
        print("Uploading file with post url method...")
        with open(filepath, "rb") as f:
            # Create a unique file name
            name = f"{date}_file_post_url"

            # Set transfer method to post url when sending put resquest
            # SDK will request a presigned post url, upload file to that url and then request the upload result to Pangea
            response = await share.put(file=f, name=name, transfer_method=TransferMethod.POST_URL)
            print(f"Upload success. Item ID: {response.result.object.id}")
        await share.close()
    except pe.PangeaAPIException as e:
        print(f"Share request error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    asyncio.run(main())

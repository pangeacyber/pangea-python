import datetime
import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.response import TransferMethod
from pangea.services import Share

token = os.getenv("PANGEA_SHARE_TOKEN")
assert token
url_template = os.getenv("PANGEA_URL_TEMPLATE")
assert url_template
config = PangeaConfig(base_url_template=url_template)

# Create a path name
date = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
filepath = "./share_examples/testfile.pdf"

# Create service object
share = Share(token, config=config)


def main():
    try:
        print("Uploading file with post url method...")
        with open(filepath, "rb") as f:
            # Create a unique file name
            name = f"{date}_file_post_url"

            # Set transfer method to post url when sending put resquest
            # SDK will request a presigned post url, upload file to that url and then request the upload result to Pangea
            response = share.put(file=f, name=name, transfer_method=TransferMethod.POST_URL)
            print(f"Upload success. Item ID: {response.result.object.id}")
    except pe.PangeaAPIException as e:
        print(f"Share request error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

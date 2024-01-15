import datetime
import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.response import TransferMethod
from pangea.services import Store

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
        with open(filepath, "rb") as f:
            # Create a unique file name
            name = f"{date}_file_multipart"

            # Set transfer method to multipart when sending put resquest
            response = store.put(file=f, name=name, transfer_method=TransferMethod.MULTIPART)
            print(f"Upload success. Item ID: {response.result.object.id}")
    except pe.PangeaAPIException as e:
        print(f"Store request error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

import datetime
import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import Store

token = os.getenv("PANGEA_STORE_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)

# Create a path name
date = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
path = f"/sdk_example/delete/{date}"

# Create service object
store = Store(token, config=config)


def main():
    try:
        print("Creating folder...")
        resp_create = store.folder_create(path=path)

        id = resp_create.result.object.id
        print(f"Folder created. ID: {id}")

        print("Deleting folder by ID...")
        resp_delete = store.delete(id=id)
        print(f"Delete success. Deleted {resp_delete.result.count} item/s")
    except pe.PangeaAPIException as e:
        print(f"Store request error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

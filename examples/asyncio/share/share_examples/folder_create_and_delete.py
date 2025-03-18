import asyncio
import datetime
import os

import pangea.exceptions as pe
from pangea.asyncio.services import ShareAsync
from pangea.config import PangeaConfig

token = os.getenv("PANGEA_SHARE_TOKEN")
assert token
url_template = os.getenv("PANGEA_URL_TEMPLATE")
assert url_template
config = PangeaConfig(base_url_template=url_template)

# Create a path name
date = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
path = f"/sdk_example/delete/{date}"

# Create service object
share = ShareAsync(token, config=config)


async def main():
    try:
        print("Creating folder...")
        resp_create = await share.folder_create(folder=path)

        id = resp_create.result.object.id
        print(f"Folder created. ID: {id}")

        print("Deleting folder by ID...")
        resp_delete = await share.delete(id=id)
        print(f"Delete success. Deleted {resp_delete.result.count} item/s")
        await share.close()
    except pe.PangeaAPIException as e:
        print(f"Share request error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    asyncio.run(main())

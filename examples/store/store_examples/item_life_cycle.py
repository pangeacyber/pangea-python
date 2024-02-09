import datetime
import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.response import TransferMethod
from pangea.services import Store
from pangea.services.store.store import (  # type: ignore
    ArchiveFormat,
    Authenticator,
    AuthenticatorType,
    FilterList,
    LinkType,
    ShareLinkCreateItem,
)

token = os.getenv("PANGEA_STORE_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)

# Create a path name
date = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
path = f"/sdk_example/files/{date}"
filepath_upload = "./store_examples/testfile.pdf"

# Create service object
store = Store(token, config=config)


def main():
    try:
        # Create a folder
        print("\nCreating folder...")
        resp_create = store.folder_create(path=path)
        folder_id = resp_create.result.object.id
        print(f"Folder create success. Folder ID: {folder_id}.")

        # Upload a file with path as unique param
        print("\nUploading file with path...")
        with open(filepath_upload, "rb") as f:
            filepath_put = path + f"/{date}_file_multipart_1"
            resp_put_path = store.put(file=f, path=filepath_put, transfer_method=TransferMethod.MULTIPART)

        print(
            f"Put success.\n\tItem ID: {resp_put_path.result.object.id}\n\tParent ID: {resp_put_path.result.object.parent_id}"
        )
        print(f"Metadata: {resp_put_path.result.object.metadata}. Tags: {resp_put_path.result.object.tags}")

        # Upload a file with parent id and name
        print("\nUploading file with parent id and name...")
        metadata = {"field1": "value1", "field2": "value2"}
        tags = ["tag1", "tag2"]

        with open(filepath_upload, "rb") as f:
            name = f"{date}_file_multipart_2"
            resp_put_id = store.put(
                file=f,
                parent_id=folder_id,
                name=name,
                transfer_method=TransferMethod.MULTIPART,
                metadata=metadata,
                tags=tags,
            )

        print(
            f"Put success.\n\tItem ID: {resp_put_id.result.object.id}\n\tParent ID: {resp_put_id.result.object.parent_id}"
        )
        print(f"Metadata: {resp_put_id.result.object.metadata}. Tags: {resp_put_id.result.object.tags}")

        # Update file. full metadata and tags
        print(f"\nUpdating item ID: {resp_put_path.result.object.id}")
        resp_update = store.update(id=resp_put_path.result.object.id, metadata=metadata, tags=tags)
        print(f"Update success. Item ID: {resp_update.result.object.id}")
        print(f"Metadata: {resp_update.result.object.metadata}. Tags: {resp_update.result.object.tags}")

        # Update file. add metadata and tags
        add_metadata = {"field3": "value3"}
        add_tags = ["tag3"]
        print(f"\nUpdating item ID: {resp_put_path.result.object.id}")
        resp_update_add = store.update(
            id=resp_put_path.result.object.id,
            add_metadata=add_metadata,
            add_tags=add_tags,
        )
        print(f"Update success. Item ID: {resp_update_add.result.object.id}")
        print(f"Metadata: {resp_update_add.result.object.metadata}. Tags: {resp_update_add.result.object.tags}")

        # Get archive
        print("\nGetting archive with multipart transfer method...")
        resp_get_archive = store.get_archive(
            ids=[folder_id],
            format=ArchiveFormat.ZIP,
            transfer_method=TransferMethod.MULTIPART,
        )
        print(f"Got {len(resp_get_archive.attached_files)} attached file(s).")
        print(f"Download URL: {resp_get_archive.url}")

        for af in resp_get_archive.attached_files:
            af.save("./")

        print("\nGetting archive with dest-url transfer method...")
        resp_get_archive = store.get_archive(
            ids=[folder_id],
            format=ArchiveFormat.TAR,
            transfer_method=TransferMethod.DEST_URL,
        )
        print(f"Got {len(resp_get_archive.attached_files)} attached file(s).")
        print(f"Download URL: {resp_get_archive.url}")

        # Download file
        print("\nDownloading file...")
        store.download_file(url=resp_get_archive.result.dest_url)
        store.download_file(url=resp_get_archive.result.dest_url, filename="download.tar")
        store.download_file(url=resp_get_archive.result.dest_url, dest_folder="./download/")
        store.download_file(
            url=resp_get_archive.result.dest_url,
            filename="download.tar",
            dest_folder="./download/",
        )

        # Create share link
        print("\nCreating share link...")

        # Need to create allowed authenticators to access share link
        authenticators = [Authenticator(auth_type=AuthenticatorType.PASSWORD, auth_context="somepassword")]

        # Create share link list, including all the items to share
        link_list = [
            ShareLinkCreateItem(
                targets=[folder_id],
                link_type=LinkType.EDITOR,
                max_access_count=3,
                authenticators=authenticators,
            )
        ]

        # Send request to create links
        resp_create_link = store.share_link_create(links=link_list)

        links = resp_create_link.result.share_link_objects
        print(f"Created {len(links)} link(s)")
        link = links[0]
        print(f"Link ID: {link.id}. Link: {link.link}")

        # Get share link
        print("\nGetting already created link by id...")
        resp_get_link = store.share_link_get(id=link.id)
        print(
            f"Got link ID: {resp_get_link.result.share_link_object.id}. Link: {resp_get_link.result.share_link_object.link}"
        )

        # List share link
        print("\nListing links...")
        resp_list_link = store.share_link_list()
        print(f"Got {resp_list_link.result.count} link(s).")

        # Delete share link
        print("\nDeleting links...")
        resp_delete_link = store.share_link_delete(ids=[link.id])
        print(f"Deleted {len(resp_delete_link.result.share_link_objects)} link(s)")

        # List files in folder
        print("\nListing objects...")
        list_filter: FilterList = {
            "folder": path,
        }
        resp_list = store.list(filter=list_filter)
        print(f"Got {resp_list.result.count} item(s)")
    except pe.PangeaAPIException as e:
        print(f"Store request error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

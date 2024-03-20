# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import io
from typing import Dict, List, Optional, Tuple, Union

import pangea.services.share.share as m
from .base import ServiceBaseAsync
from pangea.response import PangeaResponse, TransferMethod
from pangea.services.share.file_format import FileFormat
from pangea.utils import get_file_size, get_file_upload_params


class ShareAsync(ServiceBaseAsync):
    """Share service client."""

    service_name = "share"

    async def delete(
        self, id: Optional[str] = None, path: Optional[str] = None, force: Optional[bool] = None
    ) -> PangeaResponse[m.DeleteResult]:
        """
        Delete

        Delete object by ID or path. If both are supplied, the path must match
        that of the object represented by the ID.
        [**Beta API**](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: share_post_v1beta_delete

        Args:
            id (str, optional): The ID of the object to delete.
            path (str, optional): The path of the object to delete.
            force (bool, optional): If true, delete a folder even if it's not empty.

        Returns:
            A PangeaResponse. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/share).

        Examples:
            response = await share.delete(id="pos_3djfmzg2db4c6donarecbyv5begtj2bm")
        """

        input = m.DeleteRequest(id=id, path=path, force=force)
        return await self.request.post("v1beta/delete", m.DeleteResult, data=input.dict(exclude_none=True))

    async def folder_create(
        self,
        name: Optional[str] = None,
        metadata: Optional[m.Metadata] = None,
        parent_id: Optional[str] = None,
        path: Optional[str] = None,
        tags: Optional[m.Tags] = None,
    ) -> PangeaResponse[m.FolderCreateResult]:
        """
        Create a folder

        Create a folder, either by name or path and parent_id.
        [**Beta API**](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: share_post_v1beta_folder_create

        Args:
            name (str, optional): The name of an object.
            metadata (Metadata, optional): A set of string-based key/value pairs used to provide additional data about an object.
            parent_id (str, optional): The ID of a stored object.
            path (str, optional): A case-sensitive path to an object. Contains a sequence of path segments delimited by the the / character. Any path ending in a / character refers to a folder.
            tags (Tags, optional): A list of user-defined tags.

        Returns:
            A PangeaResponse. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/share).

        Examples:
            response = await share.folder_create(
                metadata={
                    "created_by": "jim",
                    "priority": "medium",
                },
                parent_id="pos_3djfmzg2db4c6donarecbyv5begtj2bm",
                path="/",
                tags=["irs_2023", "personal"],
            )
        """

        input = m.FolderCreateRequest(name=name, metadata=metadata, parent_id=parent_id, path=path, tags=tags)
        return await self.request.post("v1beta/folder/create", m.FolderCreateResult, data=input.dict(exclude_none=True))

    async def get(
        self, id: Optional[str] = None, path: Optional[str] = None, transfer_method: Optional[TransferMethod] = None
    ) -> PangeaResponse[m.GetResult]:
        """
        Get an object

        Get object. If both ID and Path are supplied, the call will fail if the
        target object doesn't match both properties.
        [**Beta API**](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: share_post_v1beta_get

        Args:
            id (str, optional): The ID of the object to retrieve.
            path (str, optional): The path of the object to retrieve.
            transfer_method (TransferMethod, optional): The requested transfer method for the file data.

        Returns:
            A PangeaResponse. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/share).

        Examples:
            response = await share.get(
                id="pos_3djfmzg2db4c6donarecbyv5begtj2bm",
                path="/",
            )
        """

        input = m.GetRequest(
            id=id,
            path=path,
            transfer_method=transfer_method,
        )
        return await self.request.post("v1beta/get", m.GetResult, data=input.dict(exclude_none=True))

    async def get_archive(
        self,
        ids: List[str] = [],
        format: Optional[m.ArchiveFormat] = None,
        transfer_method: Optional[TransferMethod] = None,
    ) -> PangeaResponse[m.GetArchiveResult]:
        """
        Get archive

        Get an archive file of multiple objects.
        [**Beta API**](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: share_post_v1beta_get_archive

        Args:
            ids (List[str]): The IDs of the objects to include in the archive. Folders include all children.
            format (ArchiveFormat, optional): The format to use for the built archive.
            transfer_method (TransferMethod, optional): The requested transfer method for the file data.

        Returns:
            A PangeaResponse. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/share).

        Examples:
            response = await share.get_archive(
                ids=["pos_3djfmzg2db4c6donarecbyv5begtj2bm"],
            )
        """

        if (
            transfer_method is not None
            and transfer_method != TransferMethod.DEST_URL
            and transfer_method != TransferMethod.MULTIPART
        ):
            raise ValueError(f"Only {TransferMethod.DEST_URL} and {TransferMethod.MULTIPART} are supported")

        input = m.GetArchiveRequest(ids=ids, format=format, transfer_method=transfer_method)
        return await self.request.post("v1beta/get_archive", m.GetArchiveResult, data=input.dict(exclude_none=True))

    async def list(
        self,
        filter: Optional[Union[Dict[str, str], m.FilterList]] = None,
        last: Optional[str] = None,
        order: Optional[m.ItemOrder] = None,
        order_by: Optional[m.ItemOrderBy] = None,
        size: Optional[int] = None,
    ) -> PangeaResponse[m.ListResult]:
        """
        List

        List or filter/search records.
        [**Beta API**](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: share_post_v1beta_list

        Args:
            filter (Union[Dict[str, str], FilterList], optional):
            last (str, optional): Reflected value from a previous response to obtain the next page of results.
            order (ItemOrder, optional): Order results asc(ending) or desc(ending).
            order_by (ItemOrderBy, optional): Which field to order results by.
            size (int, optional): Maximum results to include in the response.

        Returns:
            A PangeaResponse. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/share).

        Examples:
            response = await share.list()
        """

        input = m.ListRequest(filter=filter, last=last, order=order, order_by=order_by, size=size)
        return await self.request.post("v1beta/list", m.ListResult, data=input.dict(exclude_none=True))

    async def put(
        self,
        file: io.BufferedReader,
        name: Optional[str] = None,
        path: Optional[str] = None,
        format: Optional[FileFormat] = None,
        metadata: Optional[m.Metadata] = None,
        mimetype: Optional[str] = None,
        parent_id: Optional[str] = None,
        tags: Optional[m.Tags] = None,
        transfer_method: Optional[TransferMethod] = TransferMethod.POST_URL,
        crc32c: Optional[str] = None,
        md5: Optional[str] = None,
        sha1: Optional[str] = None,
        sha256: Optional[str] = None,
        sha512: Optional[str] = None,
        size: Optional[int] = None,
    ) -> PangeaResponse[m.PutResult]:
        """
        Upload a file

        Upload a file.
        [**Beta API**](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: share_post_v1beta_put

        Args:
            file (io.BufferedReader):
            name (str, optional): The name of the object to store.
            path (str, optional): An optional path where the file should be placed. Will auto-create directories if necessary.
            format (FileFormat, optional): The format of the file, which will be verified by the server if provided. Uploads not matching the supplied format will be rejected.
            metadata (Metadata, optional): A set of string-based key/value pairs used to provide additional data about an object.
            mimetype (str, optional): The MIME type of the file, which will be verified by the server if provided. Uploads not matching the supplied MIME type will be rejected.
            parent_id (str, optional): The parent ID of the object (a folder). Leave blank to keep in the root folder.
            tags (Tags, optional): A list of user-defined tags.
            transfer_method (TransferMethod, optional): The transfer method used to upload the file data.
            crc32c (str, optional): The hexadecimal-encoded CRC32C hash of the file data, which will be verified by the server if provided.
            md5 (str, optional): The hexadecimal-encoded MD5 hash of the file data, which will be verified by the server if provided.
            sha1 (str, optional): The hexadecimal-encoded SHA1 hash of the file data, which will be verified by the server if provided.
            sha256 (str, optional): The SHA256 hash of the file data, which will be verified by the server if provided.
            sha512 (str, optional): The hexadecimal-encoded SHA512 hash of the file data, which will be verified by the server if provided.
            size (str, optional): The size (in bytes) of the file. If the upload doesn't match, the call will fail.

        Returns:
            A PangeaResponse. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/share).

        Examples:
            try:
                with open("./path/to/file.pdf", "rb") as f:
                    response = await share.put(file=f)
                    print(f"Response: {response.result}")
            except pe.PangeaAPIException as e:
                print(f"Request Error: {e.response.summary}")
                for err in e.errors:
                    print(f"\\t{err.detail} \\n")
        """

        files: List[Tuple] = [("upload", (name, file, "application/octet-stream"))]

        if transfer_method == TransferMethod.POST_URL:
            params = get_file_upload_params(file)
            crc32c = params.crc_hex
            sha256 = params.sha256_hex
            size = params.size
        elif size is None and get_file_size(file=file) == 0:
            # Needed to upload zero byte files
            size = 0

        input = m.PutRequest(
            name=name,
            format=format,
            metadata=metadata,
            mimetype=mimetype,
            parent_id=parent_id,
            path=path,
            tags=tags,
            transfer_method=transfer_method,
            crc32c=crc32c,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            sha512=sha512,
            size=size,
        )
        data = input.dict(exclude_none=True)
        return await self.request.post("v1beta/put", m.PutResult, data=data, files=files)

    async def request_upload_url(
        self,
        name: Optional[str] = None,
        path: Optional[str] = None,
        format: Optional[FileFormat] = None,
        metadata: Optional[m.Metadata] = None,
        mimetype: Optional[str] = None,
        parent_id: Optional[str] = None,
        tags: Optional[m.Tags] = None,
        transfer_method: Optional[TransferMethod] = TransferMethod.PUT_URL,
        md5: Optional[str] = None,
        sha1: Optional[str] = None,
        sha512: Optional[str] = None,
        crc32c: Optional[str] = None,
        sha256: Optional[str] = None,
        size: Optional[int] = None,
    ) -> PangeaResponse[m.PutResult]:
        """
        Request upload URL

        Request an upload URL.
        [**Beta API**](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: share_post_v1beta_put 2

        Args:
            name (str, optional): The name of the object to store.
            path (str, optional): An optional path where the file should be placed. Will auto-create directories if necessary.
            format (FileFormat, optional): The format of the file, which will be verified by the server if provided. Uploads not matching the supplied format will be rejected.
            metadata (Metadata, optional): A set of string-based key/value pairs used to provide additional data about an object.
            mimetype (str, optional): The MIME type of the file, which will be verified by the server if provided. Uploads not matching the supplied MIME type will be rejected.
            parent_id (str, optional): The parent ID of the object (a folder). Leave blank to keep in the root folder.
            tags (Tags, optional): A list of user-defined tags.
            transfer_method (TransferMethod, optional): The transfer method used to upload the file data.
            md5 (str, optional): The hexadecimal-encoded MD5 hash of the file data, which will be verified by the server if provided.
            sha1 (str, optional): The hexadecimal-encoded SHA1 hash of the file data, which will be verified by the server if provided.
            sha512 (str, optional): The hexadecimal-encoded SHA512 hash of the file data, which will be verified by the server if provided.
            crc32c (str, optional): The hexadecimal-encoded CRC32C hash of the file data, which will be verified by the server if provided.
            sha256 (str, optional): The SHA256 hash of the file data, which will be verified by the server if provided.
            size (str, optional): The size (in bytes) of the file. If the upload doesn't match, the call will fail.

        Returns:
            A PangeaResponse. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/share).

        Examples:
            response = await share.request_upload_url(
                transfer_method=TransferMethod.POST_URL,
                crc32c="515f7c32",
                sha256="c0b56b1a154697f79d27d57a3a2aad4c93849aa2239cd23048fc6f45726271cc",
                size=222089,
                metadata={
                    "created_by": "jim",
                    "priority": "medium",
                },
                parent_id="pos_3djfmzg2db4c6donarecbyv5begtj2bm",
                path="/",
                tags=["irs_2023", "personal"],
            )
        """

        input = m.PutRequest(
            name=name,
            format=format,
            metadata=metadata,
            mimetype=mimetype,
            parent_id=parent_id,
            path=path,
            tags=tags,
            transfer_method=transfer_method,
            crc32c=crc32c,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            sha512=sha512,
            size=size,
        )

        data = input.dict(exclude_none=True)
        return await self.request.request_presigned_url("v1beta/put", m.PutResult, data=data)

    async def update(
        self,
        id: Optional[str] = None,
        path: Optional[str] = None,
        add_metadata: Optional[m.Metadata] = None,
        remove_metadata: Optional[m.Metadata] = None,
        metadata: Optional[m.Metadata] = None,
        add_tags: Optional[m.Tags] = None,
        remove_tags: Optional[m.Tags] = None,
        tags: Optional[m.Tags] = None,
        parent_id: Optional[str] = None,
        updated_at: Optional[str] = None,
    ) -> PangeaResponse[m.UpdateResult]:
        """
        Update a file

        Update a file.
        [**Beta API**](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: share_post_v1beta_update

        Args:
            id (str, optional): An identifier for the file to update.
            path (str, optional): An alternative to ID for providing the target file.
            add_metadata (Metadata, optional): A list of Metadata key/values to set in the object. If a provided key exists, the value will be replaced.
            remove_metadata (Metadata, optional): A list of Metadata key/values to remove in the object. It is not an error for a provided key to not exist. If a provided key exists but doesn't match the provided value, it will not be removed.
            metadata (Metadata, optional): Set the object's Metadata.
            add_tags (Tags, optional): A list of Tags to add. It is not an error to provide a tag which already exists.
            remove_tags (Tags, optional): A list of Tags to remove. It is not an error to provide a tag which is not present.
            tags (Tags, optional): Set the object's Tags.
            parent_id (str, optional): Set the parent (folder) of the object.
            updated_at (str, optional): The date and time the object was last updated. If included, the update will fail if this doesn't match what's stored.

        Returns:
            A PangeaResponse. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/share).

        Examples:
            response = await share.update(
                id="pos_3djfmzg2db4c6donarecbyv5begtj2bm",
                remove_metadata={
                    "created_by": "jim",
                    "priority": "medium",
                },
                remove_tags=["irs_2023", "personal"],
            )
        """

        input = m.UpdateRequest(
            id=id,
            path=path,
            add_metadata=add_metadata,
            remove_metadata=remove_metadata,
            metadata=metadata,
            add_tags=add_tags,
            remove_tags=remove_tags,
            tags=tags,
            parent_id=parent_id,
            updated_at=updated_at,
        )
        return await self.request.post("v1beta/update", m.UpdateResult, data=input.dict(exclude_none=True))

    async def share_link_create(self, links: List[m.ShareLinkCreateItem]) -> PangeaResponse[m.ShareLinkCreateResult]:
        """
        Create share links

        Create a share link.
        [**Beta API**](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: share_post_v1beta_share_link_create

        Args:
            links (List[ShareLinkCreateItem]):

        Returns:
            A PangeaResponse. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/share).

        Examples:
            response = await share.share_link_create(
                links=[
                    {
                        targets: ["pos_3djfmzg2db4c6donarecbyv5begtj2bm"],
                        link_type: LinkType.DOWNLOAD,
                        authenticators: [
                            {
                                "auth_type": AuthenticatorType.PASSWORD,
                                "auth_context": "my_fav_Pa55word",
                            }
                        ],
                    }
                ],
            )
        """

        input = m.ShareLinkCreateRequest(links=links)
        return await self.request.post(
            "v1beta/share/link/create", m.ShareLinkCreateResult, data=input.dict(exclude_none=True)
        )

    async def share_link_get(self, id: str) -> PangeaResponse[m.ShareLinkGetResult]:
        """
        Get share link

        Get a share link.
        [**Beta API**](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: share_post_v1beta_share_link_get

        Args:
            id (str, optional): The ID of a share link.

        Returns:
            A PangeaResponse. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/share).

        Examples:
            response = await share.share_link_get(
                id="psl_3djfmzg2db4c6donarecbyv5begtj2bm"
            )
        """

        input = m.ShareLinkGetRequest(id=id)
        return await self.request.post(
            "v1beta/share/link/get", m.ShareLinkGetResult, data=input.dict(exclude_none=True)
        )

    async def share_link_list(
        self,
        filter: Optional[Union[Dict[str, str], m.FilterShareLinkList]] = None,
        last: Optional[str] = None,
        order: Optional[m.ItemOrder] = None,
        order_by: Optional[m.ShareLinkOrderBy] = None,
        size: Optional[int] = None,
    ) -> PangeaResponse[m.ShareLinkListResult]:
        """
        List share links

        Look up share links by filter options.
        [**Beta API**](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: share_post_v1beta_share_link_list

        Args:
            filter (Union[Dict[str, str], ShareLinkListFilter], optional):
            last (str, optional): Reflected value from a previous response to obtain the next page of results.
            order (ItemOrder, optional): Order results asc(ending) or desc(ending).
            order_by (ItemOrderBy, optional): Which field to order results by.
            size (int, optional): Maximum results to include in the response.

        Returns:
            A PangeaResponse. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/share).

        Examples:
            response = await share.share_link_list()
        """

        input = m.ShareLinkListRequest(filter=filter, last=last, order=order, order_by=order_by, size=size)
        return await self.request.post(
            "v1beta/share/link/list", m.ShareLinkListResult, data=input.dict(exclude_none=True)
        )

    async def share_link_delete(self, ids: List[str]) -> PangeaResponse[m.ShareLinkDeleteResult]:
        """
        Delete share links

        Delete share links.
        [**Beta API**](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: share_post_v1beta_share_link_delete

        Args:
            ids (List[str]): list of the share link's id to delete

        Returns:
            A PangeaResponse. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/share).

        Examples:
            response = await share.share_link_delete(
                ids=["psl_3djfmzg2db4c6donarecbyv5begtj2bm"]
            )
        """

        input = m.ShareLinkDeleteRequest(ids=ids)
        return await self.request.post(
            "v1beta/share/link/delete", m.ShareLinkDeleteResult, data=input.dict(exclude_none=True)
        )

    async def share_link_send(
        self, links: List[m.ShareLinkSendItem], sender_email: str, sender_name: Optional[str] = None
    ) -> PangeaResponse[m.ShareLinkSendResult]:
        """
        Send share links

        Send a secure share-link notification to a set of email addresses. The
        notification email will contain an Open button that the recipient can
        use to follow the secured share-link to authenticate and then access the
        shared content.
        [**Beta API**](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: share_post_v1beta_share_link_send

        Args:
            sender_email: An email address.

        Returns:
            A PangeaResponse. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/share).

        Examples:
            response = await share.share_link_send(
                links=[ShareLinkSendItem(id=link.id, email="foo@example.org")],
                sender_email="sender@example.org",
            )
        """

        input = m.ShareLinkSendRequest(links=links, sender_email=sender_email, sender_name=sender_name)
        return await self.request.post(
            "v1beta/share/link/send", m.ShareLinkSendResult, data=input.dict(exclude_none=True)
        )

# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import enum
import io
from typing import Dict, List, NewType, Optional, Tuple, Union

from ..base import ServiceBase
from .file_format import FileFormat
from pangea.response import APIRequestModel, PangeaResponse, PangeaResponseResult, TransferMethod
from pangea.utils import get_file_size, get_file_upload_params

Metadata = NewType("Metadata", Dict[str, str])
Tags = NewType("Tags", List[str])


class ItemOrder(str, enum.Enum):
    ASC = "asc"
    DESC = "desc"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class ArchiveFormat(str, enum.Enum):
    TAR = "tar"
    ZIP = "zip"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class LinkType(str, enum.Enum):
    UPLOAD = "upload"
    DOWNLOAD = "download"
    EDITOR = "editor"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class AuthenticatorType(str, enum.Enum):
    EMAIL_OTP = "email_otp"
    PASSWORD = "password"
    SMS_OTP = "sms_otp"
    SOCIAL = "social"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class ItemOrderBy(str, enum.Enum):
    ID = "id"
    CREATED_AT = "created_at"
    NAME = "name"
    PARENT_ID = "parent_id"
    TYPE = "type"
    UPDATED_AT = "updated_at"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class ShareLinkOrderBy(str, enum.Enum):
    ID = "id"
    STORAGE_POOL_ID = "storage_pool_id"
    TARGET = "target"
    LINK_TYPE = "link_type"
    ACCESS_COUNT = "access_count"
    MAX_ACCESS_COUNT = "max_access_count"
    CREATED_AT = "created_at"
    EXPIRES_AT = "expires_at"
    LAST_ACCESSED_AT = "last_accessed_at"
    LINK = "link"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class DeleteRequest(APIRequestModel):
    id: Optional[str] = None
    force: Optional[bool] = None
    path: Optional[str] = None


class ItemData(PangeaResponseResult):
    id: str
    type: str
    name: str
    created_at: str
    updated_at: str
    size: Optional[int] = None
    billable_size: Optional[int] = None
    location: Optional[str] = None
    tags: Optional[Tags] = None
    metadata: Optional[Metadata] = None
    md5: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None
    parent_id: Optional[str] = None


class DeleteResult(PangeaResponseResult):
    count: int


class FolderCreateRequest(APIRequestModel):
    name: Optional[str] = None
    metadata: Optional[Metadata] = None
    parent_id: Optional[str] = None
    path: Optional[str] = None
    tags: Optional[Tags] = None


class FolderCreateResult(PangeaResponseResult):
    object: ItemData


class GetRequest(APIRequestModel):
    id: Optional[str] = None
    path: Optional[str] = None
    transfer_method: Optional[TransferMethod] = None


class GetResult(PangeaResponseResult):
    object: ItemData
    dest_url: Optional[str] = None


class PutRequest(APIRequestModel):
    name: Optional[str] = None
    format: Optional[FileFormat] = None
    metadata: Optional[Metadata] = None
    mimetype: Optional[str] = None
    parent_id: Optional[str] = None
    path: Optional[str] = None
    crc32c: Optional[str] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None
    size: Optional[int] = None
    tags: Optional[Tags] = None
    transfer_method: Optional[TransferMethod] = None


class PutResult(PangeaResponseResult):
    object: ItemData


class UpdateRequest(APIRequestModel):
    id: Optional[str]
    path: Optional[str] = None
    add_metadata: Optional[Metadata] = None
    remove_metadata: Optional[Metadata] = None
    metadata: Optional[Metadata] = None
    add_tags: Optional[Tags] = None
    remove_tags: Optional[Tags] = None
    tags: Optional[Tags] = None
    parent_id: Optional[str] = None
    updated_at: Optional[str] = None


class UpdateResult(PangeaResponseResult):
    object: ItemData


class FilterList(APIRequestModel):
    folder: str


class ListRequest(APIRequestModel):
    filter: Optional[Union[Dict[str, str], FilterList]] = None
    last: Optional[str] = None
    order: Optional[ItemOrder] = None
    order_by: Optional[ItemOrderBy] = None
    size: Optional[int] = None


class ListResult(PangeaResponseResult):
    count: int
    last: Optional[str] = None
    objects: List[ItemData]


class GetArchiveRequest(APIRequestModel):
    ids: List[str] = []
    format: Optional[ArchiveFormat] = None
    transfer_method: Optional[TransferMethod] = None


class GetArchiveResult(PangeaResponseResult):
    dest_url: Optional[str] = None
    count: int


class Authenticator(PangeaResponseResult):
    auth_type: AuthenticatorType
    auth_context: str


class ShareLinkItemBase(PangeaResponseResult):
    targets: List[str] = []
    link_type: Optional[LinkType] = None
    expires_at: Optional[str] = None
    max_access_count: Optional[int] = None
    authenticators: List[Authenticator]
    message: Optional[str] = None
    title: Optional[str] = None
    notify_email: Optional[str] = None
    tags: Optional[Tags] = None


class ShareLinkCreateItem(ShareLinkItemBase):
    pass


class ShareLinkCreateRequest(APIRequestModel):
    links: List[ShareLinkCreateItem] = []


class ShareLinkItem(ShareLinkItemBase):
    id: str
    storage_pool_id: str
    access_count: int
    created_at: str
    last_accessed_at: Optional[str] = None
    link: str


class ShareLinkCreateResult(PangeaResponseResult):
    share_link_objects: List[ShareLinkItem] = []


class ShareLinkGetRequest(APIRequestModel):
    id: str


class ShareLinkGetResult(PangeaResponseResult):
    share_link_object: ShareLinkItem


class FilterShareLinkList(APIRequestModel):
    id: Optional[str] = None
    id__contains: Optional[List[str]] = None
    id__in: Optional[List[str]] = None
    storage_pool_id: Optional[str] = None
    storage_pool_id__contains: Optional[List[str]] = None
    storage_pool_id__in: Optional[List[str]] = None
    target: Optional[str] = None
    target__contains: Optional[List[str]] = None
    target__in: Optional[List[str]] = None
    link_type: Optional[str] = None
    link_type__contains: Optional[List[str]] = None
    link_type__in: Optional[List[str]] = None
    access_count: Optional[int] = None
    access_count__gt: Optional[int] = None
    access_count__gte: Optional[int] = None
    access_count__lt: Optional[int] = None
    access_count__lte: Optional[int] = None
    max_access_count: Optional[int] = None
    max_access_count__gt: Optional[int] = None
    max_access_count__gte: Optional[int] = None
    max_access_count__lt: Optional[int] = None
    max_access_count__lte: Optional[int] = None
    created_at: Optional[str] = None
    created_at__gt: Optional[str] = None
    created_at__gte: Optional[str] = None
    created_at__lt: Optional[str] = None
    created_at__lte: Optional[str] = None
    expires_at: Optional[str] = None
    expires_at__gt: Optional[str] = None
    expires_at__gte: Optional[str] = None
    expires_at__lt: Optional[str] = None
    expires_at__lte: Optional[str] = None
    last_accessed_at: Optional[str] = None
    last_accessed_at__gt: Optional[str] = None
    last_accessed_at__gte: Optional[str] = None
    last_accessed_at__lt: Optional[str] = None
    last_accessed_at__lte: Optional[str] = None
    link: Optional[str] = None
    link__contains: Optional[List[str]] = None
    link__in: Optional[List[str]] = None


class ShareLinkListRequest(APIRequestModel):
    filter: Optional[Union[FilterShareLinkList, Dict[str, str]]] = None
    last: Optional[str] = None
    order: Optional[ItemOrder] = None
    order_by: Optional[ShareLinkOrderBy] = None
    size: Optional[int] = None


class ShareLinkListResult(PangeaResponseResult):
    count: int
    share_link_objects: List[ShareLinkItem] = []


class ShareLinkDeleteRequest(APIRequestModel):
    ids: List[str]


class ShareLinkDeleteResult(PangeaResponseResult):
    share_link_objects: List[ShareLinkItem] = []


class ShareLinkSendItem(APIRequestModel):
    id: str
    email: str


class ShareLinkSendRequest(APIRequestModel):
    links: List[ShareLinkSendItem]
    sender_email: str
    sender_name: Optional[str]


class ShareLinkSendResult(PangeaResponseResult):
    share_link_objects: List[ShareLinkItem]


class Share(ServiceBase):
    """Share service client."""

    service_name = "share"

    def delete(
        self, id: Optional[str] = None, path: Optional[str] = None, force: Optional[bool] = None
    ) -> PangeaResponse[DeleteResult]:
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
            response = share.delete(id="pos_3djfmzg2db4c6donarecbyv5begtj2bm")
        """
        input = DeleteRequest(id=id, path=path, force=force)
        return self.request.post("v1beta/delete", DeleteResult, data=input.dict(exclude_none=True))

    def folder_create(
        self,
        name: Optional[str] = None,
        metadata: Optional[Metadata] = None,
        parent_id: Optional[str] = None,
        path: Optional[str] = None,
        tags: Optional[Tags] = None,
    ) -> PangeaResponse[FolderCreateResult]:
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
            response = share.folder_create(
                metadata={
                    "created_by": "jim",
                    "priority": "medium",
                },
                parent_id="pos_3djfmzg2db4c6donarecbyv5begtj2bm",
                path="/",
                tags=["irs_2023", "personal"],
            )
        """
        input = FolderCreateRequest(name=name, metadata=metadata, parent_id=parent_id, path=path, tags=tags)
        return self.request.post("v1beta/folder/create", FolderCreateResult, data=input.dict(exclude_none=True))

    def get(
        self, id: Optional[str] = None, path: Optional[str] = None, transfer_method: Optional[TransferMethod] = None
    ) -> PangeaResponse[GetResult]:
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
            response = share.get(
                id="pos_3djfmzg2db4c6donarecbyv5begtj2bm",
                path="/",
            )
        """
        input = GetRequest(
            id=id,
            path=path,
            transfer_method=transfer_method,
        )
        return self.request.post("v1beta/get", GetResult, data=input.dict(exclude_none=True))

    def get_archive(
        self,
        ids: List[str] = [],
        format: Optional[ArchiveFormat] = None,
        transfer_method: Optional[TransferMethod] = None,
    ) -> PangeaResponse[GetArchiveResult]:
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
            response = share.get_archive(
                ids=["pos_3djfmzg2db4c6donarecbyv5begtj2bm"],
            )
        """
        if (
            transfer_method is not None
            and transfer_method != TransferMethod.DEST_URL
            and transfer_method != TransferMethod.MULTIPART
        ):
            raise ValueError(f"Only {TransferMethod.DEST_URL} and {TransferMethod.MULTIPART} are supported")

        input = GetArchiveRequest(ids=ids, format=format, transfer_method=transfer_method)
        return self.request.post("v1beta/get_archive", GetArchiveResult, data=input.dict(exclude_none=True))

    def list(
        self,
        filter: Optional[Union[Dict[str, str], FilterList]] = None,
        last: Optional[str] = None,
        order: Optional[ItemOrder] = None,
        order_by: Optional[ItemOrderBy] = None,
        size: Optional[int] = None,
    ) -> PangeaResponse[ListResult]:
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
            response = share.list()
        """
        input = ListRequest(filter=filter, last=last, order=order, order_by=order_by, size=size)
        return self.request.post("v1beta/list", ListResult, data=input.dict(exclude_none=True))

    def put(
        self,
        file: io.BufferedReader,
        name: Optional[str] = None,
        path: Optional[str] = None,
        format: Optional[FileFormat] = None,
        metadata: Optional[Metadata] = None,
        mimetype: Optional[str] = None,
        parent_id: Optional[str] = None,
        tags: Optional[Tags] = None,
        transfer_method: Optional[TransferMethod] = TransferMethod.POST_URL,
        crc32c: Optional[str] = None,
        md5: Optional[str] = None,
        sha1: Optional[str] = None,
        sha256: Optional[str] = None,
        sha512: Optional[str] = None,
        size: Optional[int] = None,
    ) -> PangeaResponse[PutResult]:
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
                    response = share.put(file=f)
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

        input = PutRequest(
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
        return self.request.post("v1beta/put", PutResult, data=data, files=files)

    def request_upload_url(
        self,
        name: Optional[str] = None,
        path: Optional[str] = None,
        format: Optional[FileFormat] = None,
        metadata: Optional[Metadata] = None,
        mimetype: Optional[str] = None,
        parent_id: Optional[str] = None,
        tags: Optional[Tags] = None,
        transfer_method: Optional[TransferMethod] = TransferMethod.PUT_URL,
        md5: Optional[str] = None,
        sha1: Optional[str] = None,
        sha512: Optional[str] = None,
        crc32c: Optional[str] = None,
        sha256: Optional[str] = None,
        size: Optional[int] = None,
    ) -> PangeaResponse[PutResult]:
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
            response = share.request_upload_url(
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
        input = PutRequest(
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
        return self.request.request_presigned_url("v1beta/put", PutResult, data=data)

    def update(
        self,
        id: Optional[str] = None,
        path: Optional[str] = None,
        add_metadata: Optional[Metadata] = None,
        remove_metadata: Optional[Metadata] = None,
        metadata: Optional[Metadata] = None,
        add_tags: Optional[Tags] = None,
        remove_tags: Optional[Tags] = None,
        tags: Optional[Tags] = None,
        parent_id: Optional[str] = None,
        updated_at: Optional[str] = None,
    ) -> PangeaResponse[UpdateResult]:
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
            response = share.update(
                id="pos_3djfmzg2db4c6donarecbyv5begtj2bm",
                remove_metadata={
                    "created_by": "jim",
                    "priority": "medium",
                },
                remove_tags=["irs_2023", "personal"],
            )
        """
        input = UpdateRequest(
            id=id,  # noqa: F401
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
        return self.request.post("v1beta/update", UpdateResult, data=input.dict(exclude_none=True))

    def share_link_create(self, links: List[ShareLinkCreateItem]) -> PangeaResponse[ShareLinkCreateResult]:
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
            response = share.share_link_create(
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
        input = ShareLinkCreateRequest(links=links)
        return self.request.post("v1beta/share/link/create", ShareLinkCreateResult, data=input.dict(exclude_none=True))

    def share_link_get(self, id: str) -> PangeaResponse[ShareLinkGetResult]:
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
            response = share.share_link_get(
                id="psl_3djfmzg2db4c6donarecbyv5begtj2bm"
            )
        """
        input = ShareLinkGetRequest(id=id)
        return self.request.post("v1beta/share/link/get", ShareLinkGetResult, data=input.dict(exclude_none=True))

    def share_link_list(
        self,
        filter: Optional[Union[Dict[str, str], FilterShareLinkList]] = None,
        last: Optional[str] = None,
        order: Optional[ItemOrder] = None,
        order_by: Optional[ShareLinkOrderBy] = None,
        size: Optional[int] = None,
    ) -> PangeaResponse[ShareLinkListResult]:
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
            response = share.share_link_list()
        """
        input = ShareLinkListRequest(filter=filter, last=last, order=order, order_by=order_by, size=size)
        return self.request.post("v1beta/share/link/list", ShareLinkListResult, data=input.dict(exclude_none=True))

    def share_link_delete(self, ids: List[str]) -> PangeaResponse[ShareLinkDeleteResult]:
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
            response = share.share_link_delete(
                ids=["psl_3djfmzg2db4c6donarecbyv5begtj2bm"]
            )
        """
        input = ShareLinkDeleteRequest(ids=ids)
        return self.request.post("v1beta/share/link/delete", ShareLinkDeleteResult, data=input.dict(exclude_none=True))

    def share_link_send(
        self, links: List[ShareLinkSendItem], sender_email: str, sender_name: Optional[str] = None
    ) -> PangeaResponse[ShareLinkSendResult]:
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
            response = share.share_link_send(
                links=[ShareLinkSendItem(id=link.id, email="foo@example.org")],
                sender_email="sender@example.org",
            )
        """

        input = ShareLinkSendRequest(links=links, sender_email=sender_email, sender_name=sender_name)
        return self.request.post("v1beta/share/link/send", ShareLinkSendResult, data=input.dict(exclude_none=True))

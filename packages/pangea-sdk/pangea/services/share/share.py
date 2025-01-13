# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from __future__ import annotations

import enum
import io
from typing import Dict, List, NewType, Optional, Tuple, Union

from pangea.config import PangeaConfig
from pangea.response import APIRequestModel, PangeaResponse, PangeaResponseResult, TransferMethod
from pangea.services.base import ServiceBase
from pangea.services.share.file_format import FileFormat
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
    BUCKET_ID = "bucket_id"
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
    """The ID of the object to delete."""

    force: Optional[bool] = None
    """If true, delete a folder even if it's not empty. Deletes the contents of folder as well."""

    bucket_id: Optional[str] = None
    """The bucket to use, if not the default."""


class ItemData(PangeaResponseResult):
    billable_size: Optional[int] = None
    """The number of billable bytes (includes Metadata, Tags, etc.) for the object."""

    created_at: str
    """The date and time the object was created."""

    id: str
    """The ID of a stored object."""

    md5: Optional[str] = None
    """The MD5 hash of the file contents. Cannot be written to."""

    metadata: Optional[Metadata] = None
    """A set of string-based key/value pairs used to provide additional data about an object."""

    metadata_protected: Optional[Metadata] = None
    """Protected (read-only) metadata."""

    sha256: Optional[str] = None
    """The SHA256 hash of the file contents. Cannot be written to."""

    sha512: Optional[str] = None
    """The SHA512 hash of the file contents. Cannot be written to."""

    size: Optional[int] = None
    """The size of the object in bytes."""

    tags: Optional[Tags] = None
    """A list of user-defined tags."""

    tags_protected: Optional[Tags] = None
    """Protected (read-only) flags."""

    type: str
    """The type of the item (file or dir). Cannot be written to."""

    updated_at: str
    """The date and time the object was last updated."""

    name: str
    """The name of the object."""

    folder: str
    """The full path to the folder the object is stored in."""

    parent_id: Optional[str] = None
    """The parent ID (a folder). Blanks means the root folder."""

    external_bucket_key: Optional[str] = None
    """The key in the external bucket that contains this file."""

    file_ttl: Optional[str] = None
    """The explicit file TTL setting for this object."""

    file_ttl_effective: Optional[str] = None
    """
    The effective file TTL setting for this object, either explicitly set or
    inherited (see `file_ttl_from_id`.)
    """

    file_ttl_from_id: Optional[str] = None
    """
    The ID of the object the expiry / TTL is set from. Either a service
    configuration, the object itself, or a parent folder.
    """


class DeleteResult(PangeaResponseResult):
    count: int
    """Number of objects deleted."""


class FolderCreateRequest(APIRequestModel):
    name: Optional[str] = None
    """The name of an object."""

    file_ttl: Optional[str] = None
    """Duration until files within this folder are automatically deleted."""

    metadata: Optional[Metadata] = None
    """A set of string-based key/value pairs used to provide additional data about an object."""

    root_folder: Optional[str] = None
    """
    The path of a root folder to restrict the operation to. Must resolve to
    `root_id` if also set.
    """

    root_id: Optional[str] = None
    """
    The ID of a root folder to restrict the operation to. Must match
    `root_folder` if also set.
    """

    parent_id: Optional[str] = None
    """The ID of the parent folder. Must match `folder` if also set."""

    folder: Optional[str] = None
    """The folder to place the folder in. Must match `parent_id` if also set."""

    tags: Optional[Tags] = None
    """A list of user-defined tags"""

    tenant_id: Optional[str] = None
    """A tenant to associate with this request"""

    bucket_id: Optional[str] = None
    """The bucket to use, if not the default."""


class FolderCreateResult(PangeaResponseResult):
    object: ItemData
    """Information on the created folder."""


class GetRequest(APIRequestModel):
    id: Optional[str] = None
    """The ID of the object to retrieve."""

    password: Optional[str] = None
    """If the file was protected with a password, the password to decrypt with."""

    transfer_method: Optional[TransferMethod] = None
    """The requested transfer method for the file data."""

    bucket_id: Optional[str] = None
    """The bucket to use, if not the default."""

    tenant_id: Optional[str] = None
    """A tenant to associate with this request."""


class GetResult(PangeaResponseResult):
    object: ItemData
    """File information."""

    dest_url: Optional[str] = None
    """A URL where the file can be downloaded from. (transfer_method: dest-url)"""


class PutRequest(APIRequestModel):
    transfer_method: Optional[TransferMethod] = None
    """The transfer method used to upload the file data."""

    bucket_id: Optional[str] = None
    """The bucket to use, if not the default."""

    size: Optional[int] = None
    """The size (in bytes) of the file. If the upload doesn't match, the call will fail."""

    crc32c: Optional[str] = None
    """The hexadecimal-encoded CRC32C hash of the file data, which will be verified by the server if provided."""

    sha256: Optional[str] = None
    """The SHA256 hash of the file data, which will be verified by the server if provided."""

    md5: Optional[str] = None
    """The hexadecimal-encoded MD5 hash of the file data, which will be verified by the server if provided."""

    name: Optional[str] = None
    """The name of the object to store."""

    format: Optional[FileFormat] = None
    """The format of the file, which will be verified by the server if provided. Uploads not matching the supplied format will be rejected."""

    metadata: Optional[Metadata] = None
    """A set of string-based key/value pairs used to provide additional data about an object."""

    mimetype: Optional[str] = None
    """The MIME type of the file, which will be verified by the server if provided. Uploads not matching the supplied MIME type will be rejected."""

    parent_id: Optional[str] = None
    """The parent ID of the object (a folder). Leave blank to keep in the root folder."""

    folder: Optional[str] = None
    """The path to the parent folder. Leave blank for the root folder. Path must resolve to `parent_id` if also set."""

    file_ttl: Optional[str] = None
    """The TTL before expiry for the file."""

    password: Optional[str] = None
    """An optional password to protect the file with. Downloading the file will require this password."""

    password_algorithm: Optional[str] = None
    """An optional password algorithm to protect the file with. See symmetric vault password_algorithm."""

    root_folder: Optional[str] = None
    """
    The path of a root folder to restrict the operation to. Must resolve to
    `root_id` if also set.
    """

    root_id: Optional[str] = None
    """
    The ID of a root folder to restrict the operation to. Must match
    `root_folder` if also set.
    """

    sha1: Optional[str] = None
    """The hexadecimal-encoded SHA1 hash of the file data, which will be verified by the server if provided."""

    sha512: Optional[str] = None
    """The hexadecimal-encoded SHA512 hash of the file data, which will be verified by the server if provided."""

    tags: Optional[Tags] = None
    """A list of user-defined tags"""

    tenant_id: Optional[str] = None
    """A tenant to associate with this request"""


class PutResult(PangeaResponseResult):
    object: ItemData


class UpdateRequest(APIRequestModel):
    id: Optional[str]
    """An identifier for the file to update."""

    folder: Optional[str] = None
    """
    Set the parent (folder). Leave blank for the root folder. Path must resolve
    to `parent_id` if also set.
    """

    add_metadata: Optional[Metadata] = None
    """A list of Metadata key/values to set in the object. If a provided key exists, the value will be replaced."""

    add_password: Optional[str] = None
    """Protect the file with the supplied password."""

    add_password_algorithm: Optional[str] = None
    """The algorithm to use to password protect the file."""

    add_tags: Optional[Tags] = None
    """A list of Tags to add. It is not an error to provide a tag which already exists."""

    file_ttl: Optional[str] = None
    """Set the file TTL."""

    name: Optional[str] = None
    """Sets the object's Name."""

    metadata: Optional[Metadata] = None
    """Set the object's metadata."""

    remove_metadata: Optional[Metadata] = None
    """A list of metadata key/values to remove in the object. It is not an error for a provided key to not exist. If a provided key exists but doesn't match the provided value, it will not be removed."""

    remove_password: Optional[str] = None
    """Remove the supplied password from the file."""

    remove_tags: Optional[Tags] = None
    """A list of tags to remove. It is not an error to provide a tag which is not present."""

    root_folder: Optional[str] = None
    """
    The path of a root folder to restrict the operation to. Must resolve to
    `root_id` if also set.
    """

    root_id: Optional[str] = None
    """
    The ID of a root folder to restrict the operation to. Must match
    `root_folder` if also set.
    """

    parent_id: Optional[str] = None
    """Set the parent (folder) of the object. Can be an empty string for the root folder."""

    tags: Optional[Tags] = None
    """Set the object's tags."""

    tenant_id: Optional[str] = None
    """A tenant to associate with this request."""

    updated_at: Optional[str] = None
    """The date and time the object was last updated. If included, the update will fail if this doesn't match the date and time of the last update for the object."""

    bucket_id: Optional[str] = None
    """The bucket to use, if not the default."""


class UpdateResult(PangeaResponseResult):
    object: ItemData


class FilterList(APIRequestModel):
    created_at: Optional[str] = None
    """Only records where created_at equals this value."""

    created_at__gt: Optional[str] = None
    """Only records where created_at is greater than this value."""

    created_at__gte: Optional[str] = None
    """Only records where created_at is greater than or equal to this value."""

    created_at__lt: Optional[str] = None
    """Only records where created_at is less than this value."""

    created_at__lte: Optional[str] = None
    """Only records where created_at is less than or equal to this value."""

    folder: Optional[str] = None
    """Only records where the object exists in the supplied parent folder path name."""

    id: Optional[str] = None
    """Only records where id equals this value."""

    id__in: Optional[List[str]] = None
    """Only records where id equals one of the provided substrings."""

    name: Optional[str] = None
    """Only records where name equals this value."""

    name__contains: Optional[List[str]] = None
    """Only records where name includes each substring."""

    name__in: Optional[List[str]] = None
    """Only records where name equals one of the provided substrings."""

    parent_id: Optional[str] = None
    """Only records where parent_id equals this value."""

    parent_id__in: Optional[List[str]] = None
    """Only records where parent_id equals one of the provided substrings."""

    size: Optional[int] = None
    """Only records where size equals this value."""

    size__gt: Optional[int] = None
    """Only records where size is greater than this value."""

    size__gte: Optional[int] = None
    """Only records where size is greater than or equal to this value."""

    size__lt: Optional[int] = None
    """Only records where size is less than to this value."""

    size__lte: Optional[int] = None
    """Only records where size is less than or equal to this value."""

    tags: Optional[List[str]] = None
    """A list of tags that all must be present."""

    type: Optional[str] = None
    """Only records where type equals this value."""

    type__contains: Optional[List[str]] = None
    """Only records where type includes each substring."""

    type__in: Optional[List[str]] = None
    """Only records where type equals one of the provided substrings."""

    updated_at: Optional[str] = None
    """Only records where updated_at equals this value."""

    updated_at__gt: Optional[str] = None
    """Only records where updated_at is greater than this value."""

    updated_at__gte: Optional[str] = None
    """Only records where updated_at is greater than or equal to this value."""

    updated_at__lt: Optional[str] = None
    """Only records where updated_at is less than this value."""

    updated_at__lte: Optional[str] = None
    """Only records where updated_at is less than or equal to this value."""


class ListRequest(APIRequestModel):
    filter: Optional[Union[Dict[str, str], FilterList]] = None
    last: Optional[str] = None
    """Reflected value from a previous response to obtain the next page of results."""

    order: Optional[ItemOrder] = None
    """Order results asc(ending) or desc(ending)."""

    order_by: Optional[ItemOrderBy] = None
    """Which field to order results by."""

    size: Optional[int] = None
    """Maximum results to include in the response."""

    include_external_bucket_key: bool = False
    """If true, include the `external_bucket_key` in results."""

    bucket_id: Optional[str] = None
    """The bucket to use, if not the default."""


class ListResult(PangeaResponseResult):
    count: int
    """The total number of objects matched by the list request."""

    last: Optional[str] = None
    """Used to fetch the next page of the current listing when provided in a repeated request's last parameter."""

    objects: List[ItemData]


class GetArchiveRequest(APIRequestModel):
    ids: List[str] = []
    """The IDs of the objects to include in the archive. Folders include all children."""

    format: Optional[ArchiveFormat] = None
    """The format to use to build the archive."""

    transfer_method: Optional[TransferMethod] = None
    """The requested transfer method for the file data."""

    bucket_id: Optional[str] = None
    """The bucket to use, if not the default."""


class GetArchiveResult(PangeaResponseResult):
    count: int
    """Number of objects included in the archive."""

    dest_url: Optional[str] = None
    """A location where the archive can be downloaded from. (transfer_method: dest-url)"""

    objects: List[ItemData] = []
    """A list of all objects included in the archive."""


class Authenticator(PangeaResponseResult):
    auth_type: AuthenticatorType
    """An authentication mechanism."""

    auth_context: str
    """An email address, a phone number or a password to access share link."""


class ShareLinkItemBase(PangeaResponseResult):
    targets: List[str] = []
    """List of storage IDs."""

    link_type: Optional[LinkType] = None
    """Type of link."""

    expires_at: Optional[str] = None
    """The date and time the share link expires."""

    max_access_count: Optional[int] = None
    """The maximum number of times a user can be authenticated to access the share link."""

    authenticators: Optional[List[Authenticator]] = None
    """A list of authenticators."""

    title: Optional[str] = None
    """An optional title to use in accessing shares."""

    message: Optional[str] = None
    """An optional message to use in accessing shares."""

    notify_email: Optional[str] = None
    """An email address"""

    tags: Optional[Tags] = None
    """A list of user-defined tags"""


class ShareLinkCreateItem(ShareLinkItemBase):
    pass


class ShareLinkCreateRequest(APIRequestModel):
    links: List[ShareLinkCreateItem] = []
    bucket_id: Optional[str] = None
    """The bucket to use, if not the default."""


class ShareLinkItem(ShareLinkItemBase):
    id: str
    """The ID of a share link."""

    access_count: int
    """The number of times a user has authenticated to access the share link."""

    created_at: str
    """The date and time the share link was created."""

    last_accessed_at: Optional[str] = None
    """The date and time the share link was last accessed."""

    link: Optional[str] = None
    """A URL to access the file/folders shared with a link."""

    bucket_id: str
    """The ID of a share bucket resource."""


class ShareLinkCreateResult(PangeaResponseResult):
    share_link_objects: List[ShareLinkItem] = []


class ShareLinkGetRequest(APIRequestModel):
    id: str
    """The ID of a share link."""


class ShareLinkGetResult(PangeaResponseResult):
    share_link_object: ShareLinkItem


class FilterShareLinkList(APIRequestModel):
    id: Optional[str] = None
    id__contains: Optional[List[str]] = None
    id__in: Optional[List[str]] = None
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
    title: Optional[str] = None
    title__contains: Optional[List[str]] = None
    title__in: Optional[List[str]] = None
    message: Optional[str] = None
    message__contains: Optional[List[str]] = None
    message__in: Optional[List[str]] = None
    notify_email: Optional[str] = None
    notify_email__contains: Optional[List[str]] = None
    notify_email__in: Optional[List[str]] = None
    tags: Optional[List[str]] = None


class ShareLinkListRequest(APIRequestModel):
    filter: Optional[Union[FilterShareLinkList, Dict[str, str]]] = None

    last: Optional[str] = None
    """Reflected value from a previous response to obtain the next page of results."""

    order: Optional[ItemOrder] = None
    """Order results asc(ending) or desc(ending)."""

    order_by: Optional[ShareLinkOrderBy] = None
    """Which field to order results by."""

    size: Optional[int] = None
    """Maximum results to include in the response."""

    bucket_id: Optional[str] = None
    """The bucket to use, if not the default."""


class ShareLinkListResult(PangeaResponseResult):
    count: int
    """The total number of share links matched by the list request."""

    last: Optional[str] = None
    """Used to fetch the next page of the current listing when provided in a repeated request's last parameter."""

    share_link_objects: List[ShareLinkItem] = []


class ShareLinkDeleteRequest(APIRequestModel):
    ids: List[str]
    bucket_id: Optional[str] = None
    """The bucket to use, if not the default."""


class ShareLinkDeleteResult(PangeaResponseResult):
    share_link_objects: List[ShareLinkItem] = []


class ShareLinkSendItem(APIRequestModel):
    id: str
    email: str


class ShareLinkSendRequest(APIRequestModel):
    links: List[ShareLinkSendItem]

    sender_email: str
    """An email address."""

    sender_name: Optional[str]
    """The sender name information. Can be sender's full name for example."""


class ShareLinkSendResult(PangeaResponseResult):
    share_link_objects: List[ShareLinkItem]


class Bucket(PangeaResponseResult):
    id: str
    """The ID of a share bucket resource."""

    default: bool
    """If true, is the default bucket."""

    name: str
    """The bucket's friendly name."""

    transfer_methods: List[TransferMethod]


class BucketsResult(PangeaResponseResult):
    buckets: List[Bucket]
    """A list of available buckets."""


class Share(ServiceBase):
    """Secure Share service client."""

    service_name = "share"

    def __init__(
        self, token: str, config: PangeaConfig | None = None, logger_name: str = "pangea", config_id: str | None = None
    ) -> None:
        """
        Secure Share client

        Initializes a new Secure Share client.

        Args:
            token: Pangea API token.
            config: Configuration.
            logger_name: Logger name.
            config_id: Configuration ID.

        Examples:
             config = PangeaConfig(domain="aws.us.pangea.cloud")
             authz = Share(token="pangea_token", config=config)
        """

        super().__init__(token, config, logger_name, config_id=config_id)

    def buckets(self) -> PangeaResponse[BucketsResult]:
        """
        Buckets

        Get information on the accessible buckets.

        OperationId: share_post_v1_buckets

        Returns:
            A PangeaResponse. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/share).

        Examples:
            response = share.buckets()
        """
        return self.request.post("v1/buckets", BucketsResult)

    def delete(
        self,
        id: Optional[str] = None,
        force: Optional[bool] = None,
        bucket_id: Optional[str] = None,
    ) -> PangeaResponse[DeleteResult]:
        """
        Delete

        Delete object by ID or path. If both are supplied, the path must match
        that of the object represented by the ID.

        OperationId: share_post_v1_delete

        Args:
            id (str, optional): The ID of the object to delete.
            force (bool, optional): If true, delete a folder even if it's not empty.
            bucket_id (str, optional): The bucket to use, if not the default.

        Returns:
            A PangeaResponse. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/share).

        Examples:
            response = share.delete(id="pos_3djfmzg2db4c6donarecbyv5begtj2bm")
        """
        input = DeleteRequest(id=id, force=force, bucket_id=bucket_id)
        return self.request.post("v1/delete", DeleteResult, data=input.model_dump(exclude_none=True))

    def folder_create(
        self,
        name: Optional[str] = None,
        metadata: Optional[Metadata] = None,
        parent_id: Optional[str] = None,
        folder: Optional[str] = None,
        tags: Optional[Tags] = None,
        bucket_id: Optional[str] = None,
        *,
        file_ttl: Optional[str] = None,
        root_folder: Optional[str] = None,
        root_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> PangeaResponse[FolderCreateResult]:
        """
        Create a folder

        Create a folder, either by name or path and parent_id.

        OperationId: share_post_v1_folder_create

        Args:
            name (str, optional): The name of an object.
            metadata (Metadata, optional): A set of string-based key/value pairs used to provide additional data about an object.
            parent_id (str, optional): The ID of a stored object.
            folder (str, optional): The folder to place the folder in. Must
              match `parent_id` if also set.
            tags (Tags, optional): A list of user-defined tags.
            bucket_id (str, optional): The bucket to use, if not the default.
            file_ttl: Duration until files within this folder are automatically
              deleted.
            root_folder: The path of a root folder to restrict the operation to.
              Must resolve to `root_id` if also set.
            root_id: The ID of a root folder to restrict the operation to. Must
              match `root_folder` if also set.
            tenant_id: A tenant to associate with this request

        Returns:
            A PangeaResponse. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/share).

        Examples:
            response = share.folder_create(
                metadata={
                    "created_by": "jim",
                    "priority": "medium",
                },
                parent_id="pos_3djfmzg2db4c6donarecbyv5begtj2bm",
                folder="/",
                tags=["irs_2023", "personal"],
            )
        """
        input = FolderCreateRequest(
            name=name,
            metadata=metadata,
            parent_id=parent_id,
            folder=folder,
            tags=tags,
            bucket_id=bucket_id,
            file_ttl=file_ttl,
            root_folder=root_folder,
            root_id=root_id,
            tenant_id=tenant_id,
        )
        return self.request.post("v1/folder/create", FolderCreateResult, data=input.model_dump(exclude_none=True))

    def get(
        self,
        id: Optional[str] = None,
        transfer_method: Optional[TransferMethod] = None,
        bucket_id: Optional[str] = None,
        password: Optional[str] = None,
        *,
        tenant_id: Optional[str] = None,
    ) -> PangeaResponse[GetResult]:
        """
        Get an object

        Get object. If both ID and Path are supplied, the call will fail if the
        target object doesn't match both properties.

        OperationId: share_post_v1_get

        Args:
            id (str, optional): The ID of the object to retrieve.
            transfer_method (TransferMethod, optional): The requested transfer method for the file data.
            bucket_id (str, optional): The bucket to use, if not the default.
            password (str, optional): If the file was protected with a password, the password to decrypt with.
            tenant_id: A tenant to associate with this request.

        Returns:
            A PangeaResponse. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/share).

        Examples:
            response = share.get(
                id="pos_3djfmzg2db4c6donarecbyv5begtj2bm",
                folder="/",
            )
        """
        input = GetRequest(
            id=id, transfer_method=transfer_method, bucket_id=bucket_id, password=password, tenant_id=tenant_id
        )
        return self.request.post("v1/get", GetResult, data=input.model_dump(exclude_none=True))

    def get_archive(
        self,
        ids: List[str] = [],
        format: Optional[ArchiveFormat] = None,
        transfer_method: Optional[TransferMethod] = None,
        bucket_id: Optional[str] = None,
    ) -> PangeaResponse[GetArchiveResult]:
        """
        Get archive

        Get an archive file of multiple objects.

        OperationId: share_post_v1_get_archive

        Args:
            ids (List[str]): The IDs of the objects to include in the archive. Folders include all children.
            format (ArchiveFormat, optional): The format to use for the built archive.
            transfer_method (TransferMethod, optional): The requested transfer method for the file data.
            bucket_id (str, optional): The bucket to use, if not the default.

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

        input = GetArchiveRequest(ids=ids, format=format, transfer_method=transfer_method, bucket_id=bucket_id)
        return self.request.post("v1/get_archive", GetArchiveResult, data=input.model_dump(exclude_none=True))

    def list(
        self,
        filter: Optional[Union[Dict[str, str], FilterList]] = None,
        last: Optional[str] = None,
        order: Optional[ItemOrder] = None,
        order_by: Optional[ItemOrderBy] = None,
        size: Optional[int] = None,
        bucket_id: Optional[str] = None,
    ) -> PangeaResponse[ListResult]:
        """
        List

        List or filter/search records.

        OperationId: share_post_v1_list

        Args:
            filter (Union[Dict[str, str], FilterList], optional):
            last (str, optional): Reflected value from a previous response to obtain the next page of results.
            order (ItemOrder, optional): Order results asc(ending) or desc(ending).
            order_by (ItemOrderBy, optional): Which field to order results by.
            size (int, optional): Maximum results to include in the response.
            bucket_id (str, optional): The bucket to use, if not the default.

        Returns:
            A PangeaResponse. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/share).

        Examples:
            response = share.list()
        """
        input = ListRequest(filter=filter, last=last, order=order, order_by=order_by, size=size, bucket_id=bucket_id)
        return self.request.post("v1/list", ListResult, data=input.model_dump(exclude_none=True))

    def put(
        self,
        file: io.BufferedReader,
        name: Optional[str] = None,
        folder: Optional[str] = None,
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
        bucket_id: Optional[str] = None,
        password: Optional[str] = None,
        password_algorithm: Optional[str] = None,
        *,
        file_ttl: Optional[str] = None,
        root_folder: Optional[str] = None,
        root_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> PangeaResponse[PutResult]:
        """
        Upload a file

        Upload a file.

        OperationId: share_post_v1_put

        Args:
            file (io.BufferedReader):
            name (str, optional): The name of the object to store.
            folder (str, optional): The path to the parent folder. Leave blank
              for the root folder. Path must resolve to `parent_id` if also set.
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
            bucket_id (str, optional): The bucket to use, if not the default.
            password (str, optional): An optional password to protect the file with. Downloading the file will require this password.
            password_algorithm (str, optional): An optional password algorithm to protect the file with. See symmetric vault password_algorithm.
            file_ttl: The TTL before expiry for the file.
            root_folder: The path of a root folder to restrict the operation to.
              Must resolve to `root_id` if also set.
            root_id: The ID of a root folder to restrict the operation to. Must
              match `root_folder` if also set.
            tenant_id: A tenant to associate with this request.

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
            folder=folder,
            tags=tags,
            transfer_method=transfer_method,
            crc32c=crc32c,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            sha512=sha512,
            size=size,
            bucket_id=bucket_id,
            password=password,
            password_algorithm=password_algorithm,
            file_ttl=file_ttl,
            root_folder=root_folder,
            root_id=root_id,
            tenant_id=tenant_id,
        )
        data = input.model_dump(exclude_none=True)
        return self.request.post("v1/put", PutResult, data=data, files=files)

    def request_upload_url(
        self,
        name: Optional[str] = None,
        folder: Optional[str] = None,
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
        bucket_id: Optional[str] = None,
        *,
        file_ttl: Optional[str] = None,
        password: Optional[str] = None,
        password_algorithm: Optional[str] = None,
        root_folder: Optional[str] = None,
        root_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> PangeaResponse[PutResult]:
        """
        Request upload URL

        Request an upload URL.

        OperationId: share_post_v1_put 2

        Args:
            name (str, optional): The name of the object to store.
            folder (str, optional): The path to the parent folder. Leave blank
              for the root folder. Path must resolve to `parent_id` if also set.
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
            bucket_id (str, optional): The bucket to use, if not the default.
            file_ttl: The TTL before expiry for the file.
            password: An optional password to protect the file with. Downloading
              the file will require this password.
            password_algorithm: An optional password algorithm to protect the
              file with. See symmetric vault password_algorithm.
            root_folder: The path of a root folder to restrict the operation to.
              Must resolve to `root_id` if also set.
            root_id: The ID of a root folder to restrict the operation to. Must
              match `root_folder` if also set.
            tenant_id: A tenant to associate with this request.

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
                folder="/",
                tags=["irs_2023", "personal"],
            )
        """
        input = PutRequest(
            name=name,
            format=format,
            metadata=metadata,
            mimetype=mimetype,
            parent_id=parent_id,
            folder=folder,
            tags=tags,
            transfer_method=transfer_method,
            crc32c=crc32c,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            sha512=sha512,
            size=size,
            bucket_id=bucket_id,
            file_ttl=file_ttl,
            password=password,
            password_algorithm=password_algorithm,
            root_folder=root_folder,
            root_id=root_id,
            tenant_id=tenant_id,
        )

        data = input.model_dump(exclude_none=True)
        return self.request.request_presigned_url("v1/put", PutResult, data=data)

    def update(
        self,
        id: Optional[str] = None,
        folder: Optional[str] = None,
        add_metadata: Optional[Metadata] = None,
        remove_metadata: Optional[Metadata] = None,
        metadata: Optional[Metadata] = None,
        add_tags: Optional[Tags] = None,
        remove_tags: Optional[Tags] = None,
        tags: Optional[Tags] = None,
        parent_id: Optional[str] = None,
        updated_at: Optional[str] = None,
        bucket_id: Optional[str] = None,
        *,
        add_password: Optional[str] = None,
        add_password_algorithm: Optional[str] = None,
        remove_password: Optional[str] = None,
        file_ttl: Optional[str] = None,
        root_folder: Optional[str] = None,
        root_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> PangeaResponse[UpdateResult]:
        """
        Update a file

        Update a file.

        OperationId: share_post_v1_update

        Args:
            id (str, optional): An identifier for the file to update.
            folder (str, optional): Set the parent (folder). Leave blank for the
              root folder. Path must resolve to `parent_id` if also set.
            add_metadata (Metadata, optional): A list of Metadata key/values to set in the object. If a provided key exists, the value will be replaced.
            remove_metadata (Metadata, optional): A list of Metadata key/values to remove in the object. It is not an error for a provided key to not exist. If a provided key exists but doesn't match the provided value, it will not be removed.
            metadata (Metadata, optional): Set the object's Metadata.
            add_tags (Tags, optional): A list of Tags to add. It is not an error to provide a tag which already exists.
            remove_tags (Tags, optional): A list of Tags to remove. It is not an error to provide a tag which is not present.
            tags (Tags, optional): Set the object's Tags.
            parent_id (str, optional): Set the parent (folder) of the object.
            updated_at (str, optional): The date and time the object was last updated. If included, the update will fail if this doesn't match what's stored.
            bucket_id (str, optional): The bucket to use, if not the default.
            add_password: Protect the file with the supplied password.
            add_password_algorithm: The algorithm to use to password protect the
              file.
            remove_password: Remove the supplied password from the file.
            file_ttl: Set the file TTL.
            root_folder: The path of a root folder to restrict the operation to.
              Must resolve to `root_id` if also set.
            root_id: The ID of a root folder to restrict the operation to. Must
              match `root_folder` if also set.
            tenant_id: A tenant to associate with this request.

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
            id=id,
            folder=folder,
            add_metadata=add_metadata,
            remove_metadata=remove_metadata,
            metadata=metadata,
            add_tags=add_tags,
            remove_tags=remove_tags,
            tags=tags,
            parent_id=parent_id,
            updated_at=updated_at,
            bucket_id=bucket_id,
            add_password=add_password,
            add_password_algorithm=add_password_algorithm,
            remove_password=remove_password,
            file_ttl=file_ttl,
            root_folder=root_folder,
            root_id=root_id,
            tenant_id=tenant_id,
        )
        return self.request.post("v1/update", UpdateResult, data=input.model_dump(exclude_none=True))

    def share_link_create(
        self, links: List[ShareLinkCreateItem], bucket_id: Optional[str] = None
    ) -> PangeaResponse[ShareLinkCreateResult]:
        """
        Create share links

        Create a share link.

        OperationId: share_post_v1_share_link_create

        Args:
            links (List[ShareLinkCreateItem]):
            bucket_id (str, optional): The bucket to use, if not the default.

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
        input = ShareLinkCreateRequest(links=links, bucket_id=bucket_id)
        return self.request.post(
            "v1/share/link/create", ShareLinkCreateResult, data=input.model_dump(exclude_none=True)
        )

    def share_link_get(self, id: str) -> PangeaResponse[ShareLinkGetResult]:
        """
        Get share link

        Get a share link.

        OperationId: share_post_v1_share_link_get

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
        return self.request.post("v1/share/link/get", ShareLinkGetResult, data=input.model_dump(exclude_none=True))

    def share_link_list(
        self,
        filter: Optional[Union[Dict[str, str], FilterShareLinkList]] = None,
        last: Optional[str] = None,
        order: Optional[ItemOrder] = None,
        order_by: Optional[ShareLinkOrderBy] = None,
        size: Optional[int] = None,
        bucket_id: Optional[str] = None,
    ) -> PangeaResponse[ShareLinkListResult]:
        """
        List share links

        Look up share links by filter options.

        OperationId: share_post_v1_share_link_list

        Args:
            filter (Union[Dict[str, str], ShareLinkListFilter], optional):
            last (str, optional): Reflected value from a previous response to obtain the next page of results.
            order (ItemOrder, optional): Order results asc(ending) or desc(ending).
            order_by (ItemOrderBy, optional): Which field to order results by.
            size (int, optional): Maximum results to include in the response.
            bucket_id (str, optional): The bucket to use, if not the default.

        Returns:
            A PangeaResponse. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/share).

        Examples:
            response = share.share_link_list()
        """
        input = ShareLinkListRequest(
            filter=filter, last=last, order=order, order_by=order_by, size=size, bucket_id=bucket_id
        )
        return self.request.post("v1/share/link/list", ShareLinkListResult, data=input.model_dump(exclude_none=True))

    def share_link_delete(
        self, ids: List[str], bucket_id: Optional[str] = None
    ) -> PangeaResponse[ShareLinkDeleteResult]:
        """
        Delete share links

        Delete share links.

        OperationId: share_post_v1_share_link_delete

        Args:
            ids (List[str]): list of the share link's id to delete
            bucket_id (str, optional): The bucket to use, if not the default

        Returns:
            A PangeaResponse. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/share).

        Examples:
            response = share.share_link_delete(
                ids=["psl_3djfmzg2db4c6donarecbyv5begtj2bm"]
            )
        """
        input = ShareLinkDeleteRequest(ids=ids, bucket_id=bucket_id)
        return self.request.post(
            "v1/share/link/delete", ShareLinkDeleteResult, data=input.model_dump(exclude_none=True)
        )

    def share_link_send(
        self, links: List[ShareLinkSendItem], sender_email: str, sender_name: Optional[str] = None
    ) -> PangeaResponse[ShareLinkSendResult]:
        """
        Send share links

        Send a secure share-link notification to a set of email addresses. The
        notification email will contain an Open button that the recipient can
        use to follow the secured share-link to authenticate and then access the
        shared content.

        OperationId: share_post_v1_share_link_send

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
        return self.request.post("v1/share/link/send", ShareLinkSendResult, data=input.model_dump(exclude_none=True))

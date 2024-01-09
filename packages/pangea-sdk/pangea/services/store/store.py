# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import enum
import io
import logging
from typing import Dict, List, NewType, Optional, Union

from pangea.request import PangeaConfig, PangeaRequest
from pangea.response import APIRequestModel, PangeaResponse, PangeaResponseResult, TransferMethod
from pangea.utils import FileUploadParams, get_file_upload_params

from ..base import ServiceBase
from .file_format import FileFormat

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
    ALL = "all"

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
    id: str
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


class ShareLinkCreateItem(PangeaResponseResult):
    targets: List[str] = []
    link_type: Optional[LinkType] = None
    expires_at: Optional[str] = None
    max_access_count: Optional[int] = None
    authenticators: List[Authenticator]


class ShareLinkCreateRequest(APIRequestModel):
    links: List[ShareLinkCreateItem] = []


class ShareLinkItem(PangeaResponseResult):
    id: str
    storage_pool_id: str
    targets: List[str]
    link_type: str
    access_count: int
    max_access_count: int
    created_at: str
    expires_at: str
    last_accessed_at: Optional[str] = None
    authenticators: List[Authenticator]
    link: str


class ShareLinkCreateResult(PangeaResponseResult):
    share_link_objects: List[ShareLinkItem] = []


class ShareLinkGetRequest(APIRequestModel):
    id: str


class ShareLinkGetResult(PangeaResponseResult):
    share_link_object: ShareLinkItem


class ShareLinkListFilter(APIRequestModel):
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
    filter: Optional[Union[ShareLinkListFilter, Dict[str, str]]] = None
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


class Store(ServiceBase):
    """Store service client."""

    service_name = "store"

    def delete(
        self, id: Optional[str] = None, path: Optional[str] = None, force: Optional[bool] = None
    ) -> PangeaResponse[DeleteResult]:
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
        input = FolderCreateRequest(name=name, metadata=metadata, parent_id=parent_id, path=path, tags=tags)
        return self.request.post("v1beta/folder/create", FolderCreateResult, data=input.dict(exclude_none=True))

    def get(
        self, id: Optional[str] = None, path: Optional[str] = None, transfer_method: Optional[TransferMethod] = None
    ) -> PangeaResponse[GetResult]:
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
        files = [("upload", (name, file, "application/octet-stream"))]

        if transfer_method == TransferMethod.POST_URL:
            params = get_file_upload_params(file)
            crc32c = params.crc_hex
            sha256 = params.sha256_hex
            size = params.size

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
        input = UpdateRequest(
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
        return self.request.post("v1beta/update", UpdateResult, data=input.dict(exclude_none=True))

    def share_link_create(self, links: List[ShareLinkCreateItem]) -> PangeaResponse[ShareLinkCreateResult]:
        input = ShareLinkCreateRequest(links=links)
        return self.request.post("v1beta/share/link/create", ShareLinkCreateResult, data=input.dict(exclude_none=True))

    def share_link_get(self, id: str) -> PangeaResponse[ShareLinkGetResult]:
        input = ShareLinkGetRequest(id=id)
        return self.request.post("v1beta/share/link/get", ShareLinkGetResult, data=input.dict(exclude_none=True))

    def share_link_list(
        self,
        filter: Optional[Union[Dict[str, str], ShareLinkListFilter]] = None,
        last: Optional[str] = None,
        order: Optional[ItemOrder] = None,
        order_by: Optional[ItemOrderBy] = None,
        size: Optional[int] = None,
    ) -> PangeaResponse[ShareLinkListResult]:
        input = ShareLinkListRequest(filter=filter, last=last, order=order, order_by=order_by, size=size)
        return self.request.post("v1beta/share/link/list", ShareLinkListResult, data=input.dict(exclude_none=True))

    def share_link_delete(self, ids: List[str]) -> PangeaResponse[ShareLinkDeleteResult]:
        input = ShareLinkDeleteRequest(ids=ids)
        return self.request.post("v1beta/share/link/delete", ShareLinkDeleteResult, data=input.dict(exclude_none=True))


class FileUploader:
    def __init__(self):
        self.logger = logging.getLogger("pangea")
        self._request = PangeaRequest(
            config=PangeaConfig(),
            token="",
            service="StoreUploader",
            logger=self.logger,
        )

    def upload_file(
        self,
        url: str,
        name: str,
        file: io.BufferedReader,
        transfer_method: TransferMethod = TransferMethod.PUT_URL,
        file_details: Optional[Dict] = None,
    ):
        if transfer_method == TransferMethod.PUT_URL:
            files = [("file", (name, file, "application/octet-stream"))]
            self._request.put_presigned_url(url=url, files=files)
        elif transfer_method == TransferMethod.POST_URL or transfer_method == TransferMethod.DIRECT:
            files = [("file", (name, file, "application/octet-stream"))]
            self._request.post_presigned_url(url=url, data=file_details, files=files)
        else:
            raise ValueError(f"Transfer method not supported: {transfer_method}")

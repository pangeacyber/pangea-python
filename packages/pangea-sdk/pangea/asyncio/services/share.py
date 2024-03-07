# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import io
import logging
from typing import Dict, List, Optional, Union

import pangea.services.share.share as m
from pangea.asyncio.request import PangeaRequestAsync
from pangea.request import PangeaConfig
from pangea.response import PangeaResponse, TransferMethod
from pangea.services.share.file_format import FileFormat
from pangea.utils import get_file_upload_params

from .base import ServiceBaseAsync


class ShareAsync(ServiceBaseAsync):
    """Share service client."""

    service_name = "share"

    async def delete(
        self, id: Optional[str] = None, path: Optional[str] = None, force: Optional[bool] = None
    ) -> PangeaResponse[m.DeleteResult]:
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
        input = m.FolderCreateRequest(name=name, metadata=metadata, parent_id=parent_id, path=path, tags=tags)
        return await self.request.post("v1beta/folder/create", m.FolderCreateResult, data=input.dict(exclude_none=True))

    async def get(
        self, id: Optional[str] = None, path: Optional[str] = None, transfer_method: Optional[TransferMethod] = None
    ) -> PangeaResponse[m.GetResult]:
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
        files = [("upload", (name, file, "application/octet-stream"))]

        if transfer_method == TransferMethod.POST_URL:
            params = get_file_upload_params(file)
            crc32c = params.crc_hex
            sha256 = params.sha256_hex
            size = params.size

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
        input = m.ShareLinkCreateRequest(links=links)
        return await self.request.post(
            "v1beta/share/link/create", m.ShareLinkCreateResult, data=input.dict(exclude_none=True)
        )

    async def share_link_get(self, id: str) -> PangeaResponse[m.ShareLinkGetResult]:
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
        input = m.ShareLinkListRequest(filter=filter, last=last, order=order, order_by=order_by, size=size)
        return await self.request.post(
            "v1beta/share/link/list", m.ShareLinkListResult, data=input.dict(exclude_none=True)
        )

    async def share_link_delete(self, ids: List[str]) -> PangeaResponse[m.ShareLinkDeleteResult]:
        input = m.ShareLinkDeleteRequest(ids=ids)
        return await self.request.post(
            "v1beta/share/link/delete", m.ShareLinkDeleteResult, data=input.dict(exclude_none=True)
        )

    async def share_link_send(
        self, links: List[m.ShareLinkSendItem], sender_email: str, sender_name: Optional[str] = None
    ) -> PangeaResponse[m.ShareLinkSendResult]:
        input = m.ShareLinkSendRequest(links=links, sender_email=sender_email, sender_name=sender_name)
        return await self.request.post(
            "v1beta/share/link/send", m.ShareLinkSendResult, data=input.dict(exclude_none=True)
        )


class FileUploaderAsync:
    def __init__(self):
        self.logger = logging.getLogger("pangea")
        self._request = PangeaRequestAsync(
            config=PangeaConfig(),
            token="",
            service="ShareUploaderAsync",
            logger=self.logger,
        )

    async def upload_file(
        self,
        url: str,
        name: str,
        file: io.BufferedReader,
        transfer_method: TransferMethod = TransferMethod.PUT_URL,
        file_details: Optional[Dict] = None,
    ):
        if transfer_method == TransferMethod.PUT_URL:
            files = [("file", (name, file, "application/octet-stream"))]
            await self._request.put_presigned_url(url=url, files=files)
        elif transfer_method == TransferMethod.POST_URL:
            files = [("file", (name, file, "application/octet-stream"))]
            await self._request.post_presigned_url(url=url, data=file_details, files=files)
        else:
            raise ValueError(f"Transfer method not supported: {transfer_method}")

    async def close(self):
        await self._request.session.close()

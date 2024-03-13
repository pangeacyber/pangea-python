# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import io
from typing import List, Optional, Tuple

import pangea.services.sanitize as m
from pangea.response import PangeaResponse, TransferMethod
from pangea.utils import FileUploadParams, get_file_upload_params

from .base import ServiceBaseAsync


class SanitizeAsync(ServiceBaseAsync):
    service_name = "sanitize"

    async def sanitize(
        self,
        transfer_method: TransferMethod = TransferMethod.POST_URL,
        file_path: Optional[str] = None,
        file: Optional[io.BufferedReader] = None,
        source_url: Optional[str] = None,
        share_id: Optional[str] = None,
        file_scan: Optional[m.SanitizeFile] = None,
        content: Optional[m.SanitizeContent] = None,
        share_output: Optional[m.SanitizeShareOutput] = None,
        size: Optional[int] = None,
        crc32c: Optional[str] = None,
        sha256: Optional[str] = None,
        uploaded_file_name: Optional[str] = None,
        sync_call: bool = True,
    ) -> PangeaResponse[m.SanitizeResult]:
        if file or file_path:
            if file_path:
                file = open(file_path, "rb")
            if transfer_method == TransferMethod.POST_URL and (sha256 is None or crc32c is None or size is None):
                params = get_file_upload_params(file)  # type: ignore[arg-type]
                crc32c = params.crc_hex if crc32c is None else crc32c
                sha256 = params.sha256_hex if sha256 is None else sha256
                size = params.size if size is None else size
            else:
                crc32c, sha256, size = None, None, None
            files: List[Tuple] = [("upload", ("filename", file, "application/octet-stream"))]
        else:
            raise ValueError("Need to set file_path or file arguments")

        input = m.SanitizeRequest(
            transfer_method=transfer_method,
            source_url=source_url,
            share_id=share_id,
            file=file_scan,
            content=content,
            share_output=share_output,
            crc32c=crc32c,
            sha256=sha256,
            size=size,
            uploaded_file_name=uploaded_file_name,
        )
        data = input.dict(exclude_none=True)
        response = await self.request.post(
            "v1beta/sanitize", m.SanitizeResult, data=data, files=files, poll_result=sync_call
        )
        if file_path and file is not None:
            file.close()
        return response

    async def request_upload_url(
        self,
        transfer_method: TransferMethod = TransferMethod.PUT_URL,
        params: Optional[FileUploadParams] = None,
        file_scan: Optional[m.SanitizeFile] = None,
        content: Optional[m.SanitizeContent] = None,
        share_output: Optional[m.SanitizeShareOutput] = None,
        size: Optional[int] = None,
        crc32c: Optional[str] = None,
        sha256: Optional[str] = None,
        uploaded_file_name: Optional[str] = None,
    ) -> PangeaResponse[m.SanitizeResult]:
        input = m.SanitizeRequest(
            transfer_method=transfer_method,
            file=file_scan,
            content=content,
            share_output=share_output,
            crc32c=crc32c,
            sha256=sha256,
            size=size,
            uploaded_file_name=uploaded_file_name,
        )
        if params is not None and (transfer_method == TransferMethod.POST_URL):
            input.crc32c = params.crc_hex
            input.sha256 = params.sha256_hex
            input.size = params.size

        data = input.dict(exclude_none=True)
        return await self.request.request_presigned_url("v1beta/sanitize", m.SanitizeResult, data=data)

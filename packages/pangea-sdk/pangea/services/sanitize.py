# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from __future__ import annotations

import io
from typing import Dict, List, Optional, Tuple

from pangea.response import APIRequestModel, PangeaResponse, PangeaResponseResult, TransferMethod
from pangea.services.base import ServiceBase
from pangea.utils import FileUploadParams, get_file_upload_params


class SanitizeFile(APIRequestModel):
    scan_provider: Optional[str] = None
    """Provider to use for File Scan."""


class SanitizeContent(APIRequestModel):
    url_intel: Optional[bool] = None
    url_intel_provider: Optional[str] = None
    domain_intel: Optional[bool] = None
    domain_intel_provider: Optional[str] = None
    defang: Optional[bool] = None
    defang_threshold: Optional[int] = None
    redact: Optional[bool] = None
    remove_attachments: Optional[bool] = None
    remove_interactive: Optional[bool] = None


class SanitizeShareOutput(APIRequestModel):
    enabled: Optional[bool] = None
    output_folder: Optional[str] = None


class SanitizeRequest(APIRequestModel):
    transfer_method: TransferMethod = TransferMethod.POST_URL
    source_url: Optional[str] = None
    share_id: Optional[str] = None
    file: Optional[SanitizeFile] = None
    content: Optional[SanitizeContent] = None
    share_output: Optional[SanitizeShareOutput] = None
    size: Optional[int] = None
    crc32c: Optional[str] = None
    sha256: Optional[str] = None
    uploaded_file_name: Optional[str] = None


class DefangData(PangeaResponseResult):
    external_urls_count: Optional[int] = None
    external_domains_count: Optional[int] = None
    defanged_count: Optional[int] = None
    url_intel_summary: Optional[str] = None
    domain_intel_summary: Optional[str] = None


class RedactData(PangeaResponseResult):
    redaction_count: Optional[int] = None
    summary_counts: Dict = {}


class CDR(PangeaResponseResult):
    file_attachments_removed: Optional[int] = None
    interactive_contents_removed: Optional[int] = None


class SanitizeData(PangeaResponseResult):
    defang: Optional[DefangData] = None
    redact: Optional[RedactData] = None
    malicious_file: Optional[bool] = None
    cdr: Optional[CDR] = None


class SanitizeResult(PangeaResponseResult):
    dest_url: Optional[str] = None
    dest_share_id: Optional[str] = None
    data: SanitizeData
    parameters: Dict = {}


class Sanitize(ServiceBase):
    service_name = "sanitize"

    def sanitize(
        self,
        transfer_method: TransferMethod = TransferMethod.POST_URL,
        file_path: Optional[str] = None,
        file: Optional[io.BufferedReader] = None,
        source_url: Optional[str] = None,
        share_id: Optional[str] = None,
        file_scan: Optional[SanitizeFile] = None,
        content: Optional[SanitizeContent] = None,
        share_output: Optional[SanitizeShareOutput] = None,
        size: Optional[int] = None,
        crc32c: Optional[str] = None,
        sha256: Optional[str] = None,
        uploaded_file_name: Optional[str] = None,
        sync_call: bool = True,
    ) -> PangeaResponse[SanitizeResult]:
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

        input = SanitizeRequest(
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
        data = input.model_dump(exclude_none=True)
        response = self.request.post("v1beta/sanitize", SanitizeResult, data=data, files=files, poll_result=sync_call)
        if file_path and file is not None:
            file.close()
        return response

    def request_upload_url(
        self,
        transfer_method: TransferMethod = TransferMethod.PUT_URL,
        params: Optional[FileUploadParams] = None,
        file_scan: Optional[SanitizeFile] = None,
        content: Optional[SanitizeContent] = None,
        share_output: Optional[SanitizeShareOutput] = None,
        size: Optional[int] = None,
        crc32c: Optional[str] = None,
        sha256: Optional[str] = None,
        uploaded_file_name: Optional[str] = None,
    ) -> PangeaResponse[SanitizeResult]:
        input = SanitizeRequest(
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

        data = input.model_dump(exclude_none=True)
        return self.request.request_presigned_url("v1beta/sanitize", SanitizeResult, data=data)

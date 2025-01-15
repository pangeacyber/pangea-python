# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from __future__ import annotations

import io
from typing import Dict, List, Optional, Tuple

from pydantic import Field

from pangea.config import PangeaConfig
from pangea.response import APIRequestModel, PangeaResponse, PangeaResponseResult, TransferMethod
from pangea.services.base import ServiceBase
from pangea.utils import FileUploadParams, get_file_upload_params


class SanitizeFile(APIRequestModel):
    scan_provider: Optional[str] = None
    """Provider to use for File Scan."""


class SanitizeContent(APIRequestModel):
    url_intel: Optional[bool] = None
    """Perform URL Intel lookup."""

    url_intel_provider: Optional[str] = None
    """Provider to use for URL Intel."""

    domain_intel: Optional[bool] = None
    """Perform Domain Intel lookup."""

    domain_intel_provider: Optional[str] = None
    """Provider to use for Domain Intel lookup."""

    defang: Optional[bool] = None
    """Defang external links."""

    defang_threshold: Optional[int] = None
    """Defang risk threshold."""

    redact: Optional[bool] = None
    """Redact sensitive content."""

    redact_detect_only: Optional[bool] = None
    """
    If redact is enabled, avoids redacting the file and instead returns the PII
    analysis engine results. Only works if redact is enabled.
    """


class SanitizeShareOutput(APIRequestModel):
    enabled: Optional[bool] = None
    """Store Sanitized files to Pangea Secure Share."""

    output_folder: Optional[str] = None
    """
    Store Sanitized files to this Secure Share folder (will be auto-created if
    it does not exist)
    """


class SanitizeRequest(APIRequestModel):
    transfer_method: TransferMethod = TransferMethod.POST_URL
    """The transfer method used to upload the file data."""

    source_url: Optional[str] = None
    """A URL where the file to be sanitized can be downloaded."""

    share_id: Optional[str] = None
    """A Pangea Secure Share ID where the file to be Sanitized is stored."""

    file: Optional[SanitizeFile] = None
    """File."""

    content: Optional[SanitizeContent] = None
    """Content."""

    share_output: Optional[SanitizeShareOutput] = None
    """Share output."""

    size: Optional[int] = None
    """The size (in bytes) of the file. If the upload doesn't match, the call will fail."""

    crc32c: Optional[str] = None
    """The CRC32C hash of the file data, which will be verified by the server if provided."""

    sha256: Optional[str] = None
    """The hexadecimal-encoded SHA256 hash of the file data, which will be verified by the server if provided."""

    uploaded_file_name: Optional[str] = None
    """Name of the user-uploaded file, required for transfer-method 'put-url' and 'post-url'."""


class DefangData(PangeaResponseResult):
    external_urls_count: Optional[int] = None
    """Number of external links found."""

    external_domains_count: Optional[int] = None
    """Number of external domains found."""

    defanged_count: Optional[int] = None
    """Number of items defanged per provided rules and detections."""

    url_intel_summary: Optional[str] = None
    """Processed N URLs: X are malicious, Y are suspicious, Z are unknown."""

    domain_intel_summary: Optional[str] = None
    """Processed N Domains: X are malicious, Y are suspicious, Z are unknown."""


class RedactRecognizerResult(PangeaResponseResult):
    field_type: str
    """The entity name."""

    score: float
    """The certainty score that the entity matches this specific snippet."""

    text: str
    """The text snippet that matched."""

    start: int
    """The starting index of a snippet."""

    end: int
    """The ending index of a snippet."""

    redacted: bool
    """Indicates if this rule was used to anonymize a text snippet."""


class RedactData(PangeaResponseResult):
    redaction_count: int
    """Number of items redacted"""

    summary_counts: Dict[str, int] = Field(default_factory=dict)
    """Summary counts."""

    recognizer_results: Optional[List[RedactRecognizerResult]] = None
    """The scoring result of a set of rules."""


class SanitizeData(PangeaResponseResult):
    defang: Optional[DefangData] = None
    """Defang."""

    redact: Optional[RedactData] = None
    """Redact."""

    malicious_file: Optional[bool] = None
    """If the file scanned was malicious."""


class SanitizeResult(PangeaResponseResult):
    dest_url: Optional[str] = None
    """A URL where the Sanitized file can be downloaded."""

    dest_share_id: Optional[str] = None
    """Pangea Secure Share ID of the Sanitized file."""

    data: SanitizeData
    """Sanitize data."""

    parameters: Dict = {}
    """The parameters, which were passed in the request, echoed back."""


class Sanitize(ServiceBase):
    """Sanitize service client.

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import Sanitize

        PANGEA_SANITIZE_TOKEN = os.getenv("PANGEA_SANITIZE_TOKEN")
        config = PangeaConfig(domain="pangea.cloud")

        sanitize = Sanitize(token=PANGEA_SANITIZE_TOKEN, config=config)
    """

    service_name = "sanitize"

    def __init__(
        self, token: str, config: PangeaConfig | None = None, logger_name: str = "pangea", config_id: str | None = None
    ) -> None:
        """
        Sanitize client

        Initializes a new Sanitize client.

        Args:
            token: Pangea API token.
            config: Configuration.
            logger_name: Logger name.
            config_id: Configuration ID.

        Examples:
             config = PangeaConfig(domain="aws.us.pangea.cloud")
             authz = Sanitize(token="pangea_token", config=config)
        """

        super().__init__(token, config, logger_name, config_id=config_id)

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
        """
        Sanitize

        Apply file sanitization actions according to specified rules.

        OperationId: sanitize_post_v1_sanitize

        Args:
            transfer_method: The transfer method used to upload the file data.
            file_path: Path to file to sanitize.
            file: File to sanitize.
            source_url: A URL where the file to be sanitized can be downloaded.
            share_id: A Pangea Secure Share ID where the file to be sanitized is stored.
            file_scan: Options for File Scan.
            content: Options for how the file should be sanitized.
            share_output: Integration with Secure Share.
            size: The size (in bytes) of the file. If the upload doesn't match, the call will fail.
            crc32c: The CRC32C hash of the file data, which will be verified by the server if provided.
            sha256: The hexadecimal-encoded SHA256 hash of the file data, which will be verified by the server if provided.
            uploaded_file_name: Name of the user-uploaded file, required for `TransferMethod.PUT_URL` and `TransferMethod.POST_URL`.
            sync_call: Whether or not to poll on HTTP/202.

        Raises:
            PangeaAPIException: If an API error happens.

        Returns:
            The sanitized file and information on the sanitization that was
            performed.

        Examples:
            with open("/path/to/file.txt", "rb") as f:
                response = sanitize.sanitize(
                    file=f,
                    transfer_method=TransferMethod.POST_URL,
                    uploaded_file_name="uploaded_file",
                )
        """

        if transfer_method == TransferMethod.SOURCE_URL and source_url is None:
            raise ValueError("`source_url` argument is required when using `TransferMethod.SOURCE_URL`.")

        if source_url is not None and transfer_method != TransferMethod.SOURCE_URL:
            raise ValueError(
                "`transfer_method` should be `TransferMethod.SOURCE_URL` when using the `source_url` argument."
            )

        files: Optional[List[Tuple]] = None
        if file or file_path:
            if file_path:
                file = open(file_path, "rb")
            if (
                transfer_method == TransferMethod.POST_URL
                and file
                and (sha256 is None or crc32c is None or size is None)
            ):
                params = get_file_upload_params(file)
                crc32c = params.crc_hex if crc32c is None else crc32c
                sha256 = params.sha256_hex if sha256 is None else sha256
                size = params.size if size is None else size
            else:
                crc32c, sha256, size = None, None, None
            files = [("upload", ("filename", file, "application/octet-stream"))]
        elif source_url is None:
            raise ValueError("Need to set one of `file_path`, `file`, or `source_url` arguments.")

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
        try:
            response = self.request.post("v1/sanitize", SanitizeResult, data=data, files=files, poll_result=sync_call)
        finally:
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
        """
        Sanitize via presigned URL

        Apply file sanitization actions according to specified rules via a
        [presigned URL](https://pangea.cloud/docs/api/transfer-methods).

        OperationId: sanitize_post_v1_sanitize 2

        Args:
            transfer_method: The transfer method used to upload the file data.
            params: File upload parameters.
            file_scan: Options for File Scan.
            content: Options for how the file should be sanitized.
            share_output: Integration with Secure Share.
            size: The size (in bytes) of the file. If the upload doesn't match, the call will fail.
            crc32c: The CRC32C hash of the file data, which will be verified by the server if provided.
            sha256: The hexadecimal-encoded SHA256 hash of the file data, which will be verified by the server if provided.
            uploaded_file_name: Name of the user-uploaded file, required for `TransferMethod.PUT_URL` and `TransferMethod.POST_URL`.

        Raises:
            PangeaAPIException: If an API error happens.

        Returns:
            A presigned URL.

        Examples:
            presignedUrl = sanitize.request_upload_url(
                transfer_method=TransferMethod.PUT_URL,
                uploaded_file_name="uploaded_file",
            )

            # Upload file to `presignedUrl.accepted_result.put_url`.

            # Poll for Sanitize's result.
            response: PangeaResponse[SanitizeResult] = sanitize.poll_result(response=presignedUrl)
        """

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
        return self.request.request_presigned_url("v1/sanitize", SanitizeResult, data=data)

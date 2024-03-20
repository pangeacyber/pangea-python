# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import io
from typing import List, Optional, Tuple

import pangea.services.sanitize as m
from pangea.asyncio.services.base import ServiceBaseAsync
from pangea.response import PangeaResponse, TransferMethod
from pangea.utils import FileUploadParams, get_file_upload_params


class SanitizeAsync(ServiceBaseAsync):
    """Sanitize service client.

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.asyncio.services import Sanitize

        PANGEA_SANITIZE_TOKEN = os.getenv("PANGEA_SANITIZE_TOKEN")
        config = PangeaConfig(domain="pangea.cloud")

        sanitize = Sanitize(token=PANGEA_SANITIZE_TOKEN, config=config)
    """

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
        """
        Sanitize

        Apply file sanitization actions according to specified rules.
        [**Beta API**](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: sanitize_post_v1beta_sanitize

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
            with open("/path/to/file.pdf", "rb") as f:
                response = await sanitize.sanitize(
                    file=f,
                    transfer_method=TransferMethod.POST_URL,
                    uploaded_file_name="uploaded_file",
                )
        """

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
        """
        Sanitize via presigned URL

        Apply file sanitization actions according to specified rules via a
        [presigned URL](https://pangea.cloud/docs/api/presigned-urls).
        [**Beta API**](https://pangea.cloud/docs/sdk/python/#beta-releases).

        OperationId: sanitize_post_v1beta_sanitize 2

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
            presignedUrl = await sanitize.request_upload_url(
                transfer_method=TransferMethod.PUT_URL,
                uploaded_file_name="uploaded_file",
            )

            # Upload file to `presignedUrl.accepted_result.put_url`.

            # Poll for Sanitize's result.
            response: PangeaResponse[SanitizeResult] = await sanitize.poll_result(response=presignedUrl)
        """

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

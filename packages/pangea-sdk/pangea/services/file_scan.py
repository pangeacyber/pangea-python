# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import io
import logging
from typing import Dict, List, Optional

from pangea.request import PangeaConfig, PangeaRequest
from pangea.response import APIRequestModel, PangeaResponse, PangeaResponseResult, TransferMethod
from pangea.utils import FileUploadParams, get_file_upload_params

from .base import ServiceBase


class FileScanRequest(APIRequestModel):
    """
    File Scan request data

    provider (str, optional): Provider of the information. Default provider defined by the configuration.
    verbose (bool, optional): Echo back the parameters of the API in the response
    raw (bool, optional): Return additional details from the provider.
    """

    verbose: Optional[bool] = None
    raw: Optional[bool] = None
    provider: Optional[str] = None
    size: Optional[int] = None
    crc32c: Optional[str] = None
    sha256: Optional[str] = None
    source_url: Optional[str] = None
    transfer_method: TransferMethod = TransferMethod.POST_URL


class FileScanData(PangeaResponseResult):
    """
    File Scan scan result data
    """

    category: List[str]
    score: int
    verdict: str


class FileScanResult(PangeaResponseResult):
    parameters: Optional[Dict] = None
    raw_data: Optional[Dict] = None
    data: FileScanData


class FileScan(ServiceBase):
    """FileScan service client.

    Provides methods to interact with Pangea FileScan Service:
        https://pangea.cloud/docs/api/embargo

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import FileScan

        PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")

        file_scan_config = PangeaConfig(domain="aws.us.pangea.cloud")

        # Setup Pangea FileScan service
        file_scan = FileScan(token=PANGEA_TOKEN, config=file_scan_config)
    """

    service_name = "file-scan"
    version = "v1"

    def file_scan(
        self,
        file_path: Optional[str] = None,
        file: Optional[io.BufferedReader] = None,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
        provider: Optional[str] = None,
        sync_call: bool = True,
        transfer_method: TransferMethod = TransferMethod.POST_URL,
        source_url: Optional[str] = None,
    ) -> PangeaResponse[FileScanResult]:
        """
        Scan

        Scan a file for malicious content.

        OperationId: file_scan_post_v1_scan

        Args:
            file (io.BufferedReader, optional): file to be scanned (should be opened with read permissions and in binary format)
            file_path (str, optional): filepath to be opened and scanned
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider
            provider (str, optional): Scan file using this provider
            sync_call (bool, optional): True to wait until server returns a result, False to return immediately and retrieve result asynchronously

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found
                in our [API Documentation](https://pangea.cloud/docs/api/file-scan).

        Examples:
            try:
                with open("./path/to/file.pdf", "rb") as f:
                    response = client.file_scan(file=f, verbose=True, provider="crowdstrike")
                    print(f"Response: {response.result}")
            except pe.PangeaAPIException as e:
                print(f"Request Error: {e.response.summary}")
                for err in e.errors:
                    print(f"\\t{err.detail} \\n")
        """

        if file or file_path:
            if file_path:
                file = open(file_path, "rb")
            if transfer_method == TransferMethod.POST_URL:
                params = get_file_upload_params(file)
                crc = params.crc_hex
                sha = params.sha256_hex
                size = params.size
            else:
                crc, sha, size = None, None, None
            files = [("upload", ("filename", file, "application/octet-stream"))]
        else:
            raise ValueError("Need to set file_path or file arguments")

        input = FileScanRequest(
            verbose=verbose,
            raw=raw,
            provider=provider,
            crc32c=crc,
            sha256=sha,
            size=size,
            transfer_method=transfer_method,
            source_url=source_url,
        )
        data = input.dict(exclude_none=True)
        return self.request.post("v1/scan", FileScanResult, data=data, files=files, poll_result=sync_call)

    def request_upload_url(
        self,
        transfer_method: TransferMethod = TransferMethod.PUT_URL,
        params: Optional[FileUploadParams] = None,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
        provider: Optional[str] = None,
    ) -> PangeaResponse[FileScanResult]:
        input = FileScanRequest(
            verbose=verbose,
            raw=raw,
            provider=provider,
            transfer_method=transfer_method,
        )
        if params is not None and (transfer_method == TransferMethod.POST_URL):
            input.crc32c = params.crc_hex
            input.sha256 = params.sha256_hex
            input.size = params.size

        data = input.dict(exclude_none=True)
        return self.request.request_presigned_url("v1/scan", FileScanResult, data=data)


class FileUploader:
    def __init__(self):
        self.logger = logging.getLogger("pangea")
        self._request = PangeaRequest(
            config=PangeaConfig(),
            token="",
            service="FileScanUploader",
            logger=self.logger,
        )

    def upload_file(
        self,
        url: str,
        file: io.BufferedReader,
        transfer_method: TransferMethod = TransferMethod.PUT_URL,
        file_details: Optional[Dict] = None,
    ):
        if transfer_method == TransferMethod.PUT_URL:
            files = [("file", ("filename", file, "application/octet-stream"))]
            self._request.put_presigned_url(url=url, files=files)
        elif transfer_method == TransferMethod.POST_URL:
            files = [("file", ("filename", file, "application/octet-stream"))]
            self._request.post_presigned_url(url=url, data=file_details, files=files)
        else:
            raise ValueError(f"Transfer method not supported: {transfer_method}")

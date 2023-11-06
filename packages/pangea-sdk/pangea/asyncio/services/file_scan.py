# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import io
from typing import Optional

import pangea.services.file_scan as m
from pangea.response import PangeaResponse
from pangea.utils import get_presigned_url_upload_params

from .base import ServiceBaseAsync


class FileScanAsync(ServiceBaseAsync):
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

    async def file_scan(
        self,
        file_path: Optional[str] = None,
        file: Optional[io.BufferedReader] = None,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
        provider: Optional[str] = None,
        sync_call: bool = True,
    ) -> PangeaResponse[m.FileScanResult]:
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
            crc, sha, size, _ = get_presigned_url_upload_params(file)
            files = [("upload", ("filename", file, "application/octet-stream"))]
        else:
            raise ValueError("Need to set file_path or file arguments")

        input = m.FileScanRequest(
            verbose=verbose, raw=raw, provider=provider, transfer_crc32c=crc, transfer_sha256=sha, transfer_size=size
        )
        data = input.dict(exclude_none=True)
        return await self.request.post("v1/scan", m.FileScanResult, data=data, files=files, poll_result=sync_call)

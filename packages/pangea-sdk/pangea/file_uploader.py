# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import io
import logging
from typing import Dict, Optional

from pangea.request import PangeaConfig, PangeaRequest
from pangea.response import TransferMethod


class FileUploader:
    def __init__(self):
        self.logger = logging.getLogger("pangea")
        self._request = PangeaRequest(
            config=PangeaConfig(),
            token="",
            service="FileUploader",
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

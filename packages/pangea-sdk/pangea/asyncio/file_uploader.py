# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import io
import logging
from typing import Dict, Optional

from pangea.asyncio.request import PangeaRequestAsync
from pangea.request import PangeaConfig
from pangea.response import TransferMethod


class FileUploaderAsync:
    def __init__(self) -> None:
        self.logger = logging.getLogger("pangea")
        self._request: PangeaRequestAsync = PangeaRequestAsync(
            config=PangeaConfig(),
            token="",
            service="FileUploader",
            logger=self.logger,
        )

    async def upload_file(
        self,
        url: str,
        file: io.BufferedReader,
        transfer_method: TransferMethod = TransferMethod.PUT_URL,
        file_details: Optional[Dict] = None,
    ) -> None:
        if transfer_method == TransferMethod.PUT_URL:
            files = [("file", ("filename", file, "application/octet-stream"))]
            await self._request.put_presigned_url(url=url, files=files)
        elif transfer_method == TransferMethod.POST_URL:
            files = [("file", ("filename", file, "application/octet-stream"))]
            await self._request.post_presigned_url(url=url, data=file_details, files=files)  # type: ignore[arg-type]
        else:
            raise ValueError(f"Transfer method not supported: {transfer_method}")

    async def close(self) -> None:
        await self._request.session.close()

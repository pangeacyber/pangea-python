# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from __future__ import annotations

import copy
import logging
from typing import Dict, Optional, Type, Union

from typing_extensions import TypeVar

from pangea.asyncio.request import PangeaRequestAsync
from pangea.config import PangeaConfig
from pangea.exceptions import AcceptedRequestException
from pangea.request import PangeaRequest
from pangea.response import AttachedFile, PangeaResponse, PangeaResponseResult

TResult = TypeVar("TResult", bound=PangeaResponseResult, default=PangeaResponseResult)


class ServiceBase(object):
    service_name: str = "base"

    def __init__(
        self,
        token: str,
        config: PangeaConfig | None = None,
        logger_name: str = "pangea",
        config_id: str | None = None,
    ) -> None:
        """
        Initializes a new Pangea service client.

        Args:
            token: Pangea API token.
            config: Configuration.
            logger_name: Logger name.
        """
        if not token:
            raise Exception("No token provided")

        self.config = copy.deepcopy(config) if config is not None else PangeaConfig()
        self.logger = logging.getLogger(logger_name)
        self._token = token
        self.config_id: Optional[str] = config_id
        self._request: Optional[Union[PangeaRequest, PangeaRequestAsync]] = None
        extra_headers: Dict = {}
        self.request.set_extra_headers(extra_headers)

    @property
    def token(self) -> str:
        return self._token

    @token.setter
    def token(self, value: str) -> None:
        self._token = value

    @property
    def request(self) -> PangeaRequest:
        if self._request is None or isinstance(self._request, PangeaRequestAsync):
            self._request = PangeaRequest(
                config=self.config,
                token=self.token,
                service=self.service_name,
                logger=self.logger,
                config_id=self.config_id,
            )

        return self._request

    def poll_result(
        self,
        exception: Optional[AcceptedRequestException] = None,
        response: Optional[PangeaResponse] = None,
        request_id: Optional[str] = None,
        result_class: Type[TResult] = PangeaResponseResult,  # type: ignore[assignment]
    ) -> PangeaResponse[TResult]:
        """
        Poll result

        Returns request's result that has been accepted by the server

        Args:
            exception: Exception that was previously raised by the SDK on a call
              that is being processed.

        Returns:
            PangeaResponse

        Raises:
            PangeaAPIException: If an API Error happens

        Examples:
            response = service.poll_result(exception)
        """
        if exception is not None:
            return self.request.poll_result_once(exception.response, check_response=True)
        elif response is not None:
            return self.request.poll_result_once(response, check_response=True)
        elif request_id is not None:
            return self.request.poll_result_by_id(request_id=request_id, result_class=result_class, check_response=True)
        else:
            raise AttributeError("Need to set exception, response or request_id")

    def download_file(self, url: str, filename: str | None = None) -> AttachedFile:
        """
        Download file

        Download a file from the specified URL and save it with the given
        filename.

        Args:
            url: URL of the file to download
            filename: Name to save the downloaded file as. If not provided, the
              filename will be determined from the Content-Disposition header or
              the URL.
        """

        return self.request.download_file(url=url, filename=filename)

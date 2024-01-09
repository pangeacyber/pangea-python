# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import copy
import logging
from typing import Optional, Type, Union

from pangea.asyncio.request import PangeaRequestAsync
from pangea.config import PangeaConfig
from pangea.exceptions import AcceptedRequestException
from pangea.request import PangeaRequest
from pangea.response import PangeaResponse, PangeaResponseResult


class ServiceBase(object):
    service_name: str = "base"

    def __init__(
        self, token, config: Optional[PangeaConfig] = None, logger_name: str = "pangea", config_id: Optional[str] = None
    ):
        if not token:
            raise Exception("No token provided")

        self.config = config if copy.deepcopy(config) else PangeaConfig()
        self.logger = logging.getLogger(logger_name)
        self._token = token
        self.config_id: Optional[None] = config_id  # type: ignore[assignment]
        self._request: Union[PangeaRequest, PangeaRequestAsync] = None  # type: ignore[assignment]
        extra_headers = {}  # type: ignore[var-annotated]
        self.request.set_extra_headers(extra_headers)

    @property
    def token(self):
        return self._token

    @token.setter
    def token(self, value):
        self._token = value

    @property
    def request(self):
        if not self._request:
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
        result_class: Union[Type[PangeaResponseResult], dict] = dict,  # type: ignore[assignment]
    ) -> PangeaResponse:
        """
        Poll result

        Returns request's result that has been accepted by the server

        Args:
            exception (AcceptedRequestException): Exception raise by SDK on the call that is been processed.

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

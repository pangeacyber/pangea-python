# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import copy
import logging
from typing import Optional

from pangea.config import PangeaConfig
from pangea.exceptions import AcceptedRequestException
from pangea.request import PangeaRequest
from pangea.response import PangeaResponse


class ServiceBase(object):
    service_name: str = "base"

    def __init__(
        self, token, config: Optional[PangeaConfig] = None, logger_name: str = "pangea", config_id: Optional[str] = None
    ):
        if not token:
            raise Exception("No token provided")

        self.config = config if copy.deepcopy(config) else PangeaConfig()
        self.logger = logging.getLogger(logger_name)

        self.config_id: Optional[None] = config_id

        self.request = PangeaRequest(
            config=self.config,
            token=token,
            service=self.service_name,
            logger=self.logger,
            config_id=self.config_id,
        )

        extra_headers = {}
        self.request.set_extra_headers(extra_headers)

    @property
    def token(self):
        return self.request.token

    @token.setter
    def token(self, value):
        self.request.token = value

    def poll_result(self, exception: AcceptedRequestException) -> PangeaResponse:
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
        return self.request.poll_result_once(exception.response, check_response=True)

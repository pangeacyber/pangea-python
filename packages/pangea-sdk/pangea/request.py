# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import copy
import json
import logging
import time
from typing import Dict, List, Optional, Tuple, Type, Union

import pangea
import requests
from pangea import exceptions
from pangea.config import PangeaConfig
from pangea.response import PangeaResponse, PangeaResponseResult, ResponseStatus
from pangea.utils import default_encoder
from requests.adapters import HTTPAdapter, Retry


class PangeaRequest(object):
    """An object that makes direct calls to Pangea Service APIs.

    Wraps Get/Post calls to support both API requests. If `queued_retry_enabled`
    is enabled, the progress of long running Post requests will queried until
    completion or until the `poll_result_timeout` is reached. Both values can
    be set in PangeaConfig.
    """

    def __init__(
        self, config: PangeaConfig, token: str, service: str, logger: logging.Logger, config_id: Optional[str] = None
    ):
        self.config = copy.deepcopy(config)
        self.token = token
        self.service = service
        self.config_id = config_id

        # Queued request retry support flag
        self._queued_retry_enabled = config.queued_retry_enabled

        # Custom headers
        self._extra_headers = {}
        self._user_agent = ""
        self.set_custom_user_agent(config.custom_user_agent)
        self.session: requests.Session = self._init_session()

        self.logger = logger

    def __del__(self):
        self.session.close()

    def set_extra_headers(self, headers: dict):
        """Sets any additional headers in the request.

        Args:
            headers (dict): key-value pair containing extra headers to et

        Example:
            set_extra_headers({ "My-Header" : "foobar" })
        """

        if isinstance(headers, dict):
            self._extra_headers = headers

    def set_custom_user_agent(self, user_agent: str):
        self.config.custom_user_agent = user_agent
        self._user_agent = f"pangea-python/{pangea.__version__}"
        if self.config.custom_user_agent:
            self._user_agent += f" {self.config.custom_user_agent}"

    def queued_support(self, value: bool):
        """Sets or returns the queued retry support mode.

        Args:
            value (bool): true - enable queued request retry mode, false - to disable
        """
        self._queued_retry_enabled = value

        return self._queued_retry_enabled

    def post(
        self,
        endpoint: str,
        result_class: Type[PangeaResponseResult],
        data: Union[str, Dict] = {},
        files: Optional[List[Tuple]] = None,
        poll_result: bool = True,
    ) -> PangeaResponse:
        """Makes the POST call to a Pangea Service endpoint.

        Args:
            endpoint(str): The Pangea Service API endpoint.
            data(dict): The POST body payload object

        Returns:
            PangeaResponse which contains the response in its entirety and
               various properties to retrieve individual fields
        """
        url = self._url(endpoint)
        # Set config ID if available
        if self.config_id and data.pop("config_id", None) is None:
            data["config_id"] = self.config_id

        data_send = json.dumps(data, default=default_encoder) if isinstance(data, dict) else data
        self.logger.debug(
            json.dumps({"service": self.service, "action": "post", "url": url, "data": data}, default=default_encoder)
        )

        if files:
            multi = [("request", (None, data_send, "application/json"))]
            multi.extend(files)
            files = multi
            data_send = None

        requests_response = self.session.post(url, headers=self._headers(), data=data_send, files=files)
        pangea_response = PangeaResponse(requests_response, result_class=result_class)
        if poll_result:
            pangea_response = self._handle_queued_result(pangea_response)

        self.logger.debug(
            json.dumps(
                {"service": self.service, "action": "post", "url": url, "response": pangea_response.json},
                default=default_encoder,
            )
        )
        return self._check_response(pangea_response)

    def _handle_queued_result(self, response: PangeaResponse) -> PangeaResponse:
        if self._queued_retry_enabled and response.raw_response.status_code == 202:
            self.logger.debug(
                json.dumps(
                    {"service": self.service, "action": "poll_result", "response": response.json},
                    default=default_encoder,
                )
            )
            response = self._poll_result_retry(response)

        return response

    def get(self, path: str, result_class: Type[PangeaResponseResult], check_response: bool = True) -> PangeaResponse:
        """Makes the GET call to a Pangea Service endpoint.

        Args:
            endpoint(str): The Pangea Service API endpoint.
            path(str): Additional URL path

        Returns:
            PangeaResponse which contains the response in its entirety and
               various properties to retrieve individual fields
        """

        url = self._url(path)
        self.logger.debug(json.dumps({"service": self.service, "action": "get", "url": url}))
        requests_response = self.session.get(url, headers=self._headers())
        pangea_response = PangeaResponse(requests_response, result_class=result_class)

        self.logger.debug(
            json.dumps(
                {"service": self.service, "action": "get", "url": url, "response": pangea_response.json},
                default=default_encoder,
            )
        )

        if check_response is False:
            return pangea_response

        return self._check_response(pangea_response)

    def _get_delay(self, retry_count, start):
        delay = retry_count * retry_count
        now = time.time()
        # if with this delay exceed timeout, reduce delay
        if now - start + delay >= self.config.poll_result_timeout:
            delay = start + self.config.poll_result_timeout - now

        return delay

    def _reach_timeout(self, start):
        return time.time() - start >= self.config.poll_result_timeout

    def _get_poll_path(self, request_id: str):
        return f"request/{request_id}"

    def poll_result_by_id(
        self, request_id: str, result_class: Union[Type[PangeaResponseResult], dict], check_response: bool = True
    ):
        path = self._get_poll_path(request_id)
        self.logger.debug(json.dumps({"service": self.service, "action": "poll_result_once", "url": path}))
        return self.get(path, result_class, check_response=check_response)

    def poll_result_once(self, response: PangeaResponse, check_response: bool = True):
        request_id = response.request_id
        if not request_id:
            raise exceptions.PangeaException("Poll result error error: response did not include a 'request_id'")

        if response.status != ResponseStatus.ACCEPTED.value:
            raise exceptions.PangeaException("Response already proccesed")

        return self.poll_result_by_id(request_id, response.result_class, check_response=check_response)

    def _poll_result_retry(self, response: PangeaResponse) -> PangeaResponse:
        retry_count = 1
        start = time.time()

        while response.status == ResponseStatus.ACCEPTED.value and not self._reach_timeout(start):
            time.sleep(self._get_delay(retry_count, start))
            response = self.poll_result_once(response, check_response=False)
            retry_count += 1

        self.logger.debug(json.dumps({"service": self.service, "action": "poll_result_retry", "step": "exit"}))
        return self._check_response(response)

    def _init_session(self) -> requests.Session:
        retry_config = Retry(
            total=self.config.request_retries,
            backoff_factor=self.config.request_backoff,
            status_forcelist=[500, 502, 503, 504],
        )

        adapter = HTTPAdapter(max_retries=retry_config)
        session = requests.Session()

        if self.config.insecure:
            session.mount("http://", adapter)
        else:
            session.mount("https://", adapter)

        return session

    def _url(self, path: str) -> str:
        if self.config.domain.startswith("http://") or self.config.domain.startswith("https://"):
            # it's URL
            url = f"{self.config.domain}/{path}"
        else:
            schema = "http://" if self.config.insecure else "https://"
            domain = (
                self.config.domain if self.config.environment == "local" else f"{self.service}.{self.config.domain}"
            )
            url = f"{schema}{domain}/{path}"
        return url

    def _headers(self) -> dict:
        headers = {
            "User-Agent": self._user_agent,
            "Authorization": f"Bearer {self.token}",
        }

        # We want to ignore previous headers if user tryed to set them, so we will overwrite them.
        self._extra_headers.update(headers)
        return self._extra_headers

    def _check_response(self, response: PangeaResponse) -> PangeaResponse:
        status = response.status
        summary = response.summary

        if status == ResponseStatus.SUCCESS.value:
            return response

        self.logger.error(
            json.dumps(
                {
                    "service": self.service,
                    "action": "api_error",
                    "url": response.raw_response.url,
                    "summary": summary,
                    "request_id": response.request_id,
                    "result": response.raw_result,
                }
            )
        )

        if status == ResponseStatus.VALIDATION_ERR.value:
            raise exceptions.ValidationException(summary, response)
        elif status == ResponseStatus.TOO_MANY_REQUESTS.value:
            raise exceptions.RateLimitException(summary, response)
        elif status == ResponseStatus.NO_CREDIT.value:
            raise exceptions.NoCreditException(summary, response)
        elif status == ResponseStatus.UNAUTHORIZED.value:
            raise exceptions.UnauthorizedException(self.service, response)
        elif status == ResponseStatus.SERVICE_NOT_ENABLED.value:
            raise exceptions.ServiceNotEnabledException(self.service, response)
        elif status == ResponseStatus.PROVIDER_ERR.value:
            raise exceptions.ProviderErrorException(summary, response)
        elif status in (ResponseStatus.MISSING_CONFIG_ID_SCOPE.value, ResponseStatus.MISSING_CONFIG_ID.value):
            raise exceptions.MissingConfigID(self.service, response)
        elif status == ResponseStatus.SERVICE_NOT_AVAILABLE.value:
            raise exceptions.ServiceNotAvailableException(summary, response)
        elif status == ResponseStatus.TREE_NOT_FOUND.value:
            raise exceptions.TreeNotFoundException(summary, response)
        elif status == ResponseStatus.IP_NOT_FOUND.value:
            raise exceptions.IPNotFoundException(summary)
        elif status == ResponseStatus.BAD_OFFSET.value:
            raise exceptions.BadOffsetException(summary, response)
        elif status == ResponseStatus.FORBIDDEN_VAULT_OPERATION.value:
            raise exceptions.ForbiddenVaultOperation(summary, response)
        elif status == ResponseStatus.VAULT_ITEM_NOT_FOUND.value:
            raise exceptions.VaultItemNotFound(summary, response)
        elif status == ResponseStatus.NOT_FOUND.value:
            raise exceptions.NotFound(response.raw_response.url if response.raw_response is not None else "", response)
        elif status == ResponseStatus.INTERNAL_SERVER_ERROR.value:
            raise exceptions.InternalServerError(response)
        elif status == ResponseStatus.ACCEPTED.value:
            raise exceptions.AcceptedRequestException(response)
        raise exceptions.PangeaAPIException(f"{summary} ", response)

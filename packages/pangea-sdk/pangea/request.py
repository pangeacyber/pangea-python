# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import json
import logging
import time

import pangea
import requests
from pangea import exceptions
from pangea.config import PangeaConfig
from pangea.response import PangeaResponse, ResponseStatus
from requests.adapters import HTTPAdapter, Retry

logger = logging.getLogger(__name__)


class PangeaRequest(object):
    """An object that makes direct calls to Pangea Service APIs.

    Wraps Get/Post calls to support both API requests. If `queued_retry_enabled`
    is enabled, the progress of long running Post requests will queried until
    completion or until the `queued_retries` limit is reached. Both values can
    be set in PangeaConfig.
    """

    def __init__(
        self,
        config: PangeaConfig,
        token: str,
        version: str,
        service: str,
    ):
        self.config = config
        self.token = token
        self.version = version
        self.service = service

        # TODO: allow overriding these
        self.retries = config.request_retries
        self.backoff = config.request_backoff
        self.timeout = config.request_timeout

        # number of queued retry fetch attempts, with exponential backoff (4 -> 1 + 4 + 9 + 16  = 30 seconds of sleep)
        self.queued_retries = config.queued_retries

        # Queued request retry support flag
        self._queued_retry_enabled = config.queued_retry_enabled

        # Custom headers
        self._extra_headers = {}

        self.session: requests.Session = self._init_session()

    def __del__(self):
        self.session.close()

    def set_extra_headers(self, headers: dict):
        """Sets any additional headers in the request.

        Args:
            headers (dict): key-value pair containing extra headers to et

        Example:
            set_extra_headers({ "My-Header" : "foobar" })
        """
        self._extra_headers = headers

    def queued_support(self, value: bool):
        """Sets or returns the queued retry support mode.

        Args:
            value (bool): true - enable queued request retry mode, false - to disable
        """
        self._queued_retry_enabled = value

        return self._queued_retry_enabled

    def post(self, endpoint: str = "", data: dict = {}) -> PangeaResponse:
        """Makes the POST call to a Pangea Service endpoint.

        If queued_support mode is enabled, progress checks will be made for
        queued requests until processing is completed or until exponential
        backoff `queued_retries` have been reached.

        Args:
            endpoint(str): The Pangea Service API endpoint.
            data(dict): The POST body payload object

        Returns:
            PangeaResponse which contains the response in its entirety and
               various properties to retrieve individual fields
        """
        url = self._url(endpoint)

        requests_response = self.session.post(url, headers=self._headers(), data=json.dumps(data))

        if self._queued_retry_enabled and requests_response.status_code == 202:
            response_json = requests_response.json()
            request_id = response_json.get("request_id", None)

            if not request_id:
                raise Exception("Queue error: response did not include a 'request_id'")

            pangea_response = self._handle_queued(request_id)
        else:
            pangea_response = PangeaResponse(requests_response)

        self._check_response(pangea_response)
        return pangea_response

    def get(self, endpoint: str, path: str) -> PangeaResponse:
        """Makes the GET call to a Pangea Service endpoint.

        Args:
            endpoint(str): The Pangea Service API endpoint.
            path(str): Additional URL path

        Returns:
            PangeaResponse which contains the response in its entirety and
               various properties to retrieve individual fields
        """
        url = self._url(f"{endpoint}/{path}")

        requests_response = self.session.get(url, headers=self._headers())

        pangea_response = PangeaResponse(requests_response)

        self._check_response(pangea_response)
        return pangea_response

    def _handle_queued(self, request_id: str) -> PangeaResponse:
        retry_count = 1

        while True:
            time.sleep(retry_count * retry_count)
            pangea_response = self.get("request", request_id)

            if pangea_response.code == 202 and retry_count <= self.queued_retries:
                retry_count += 1
            else:
                return pangea_response

    def _init_session(self) -> requests.Session:
        retry_config = Retry(
            total=self.retries,
            backoff_factor=self.backoff,
        )

        adapter = HTTPAdapter(max_retries=retry_config)
        session = requests.Session()

        if self.config.insecure:
            session.mount("http://", adapter)
        else:
            session.mount("https://", adapter)

        return session

    def _url(self, path: str) -> str:
        protocol = "http://" if self.config.insecure else "https://"
        domain = self.config.domain if self.config.environment == "local" else f"{self.service}.{self.config.domain}"

        url = f"{protocol}{domain}/{ str(self.version) + '/' if self.version else '' }{path}"
        return url

    def _headers(self) -> dict:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"Pangea Python v{pangea.__version__}",
            "Authorization": f"Bearer {self.token}",
        }

        if self._extra_headers:
            headers.update(self._extra_headers)

        return headers

    def _check_response(self, response: PangeaResponse):
        status = response.status
        summary = response.summary

        if status == ResponseStatus.SUCCESS.value:
            return
        else:
            response.result = None

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
        raise exceptions.PangeaAPIException(f"{status}: {summary}", response)

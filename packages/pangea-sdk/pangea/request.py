# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import copy
import json
import logging
import time
from typing import Dict, List, Optional, Tuple, Type, Union

import aiohttp
import pangea
import pangea.exceptions as pe
import requests
from pangea.config import PangeaConfig
from pangea.response import AcceptedResult, PangeaResponse, PangeaResponseResult, ResponseStatus, TransferMethod
from pangea.utils import default_encoder
from requests.adapters import HTTPAdapter, Retry


class PangeaRequestBase(object):
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
        self._session: Optional[Union[requests.Session, aiohttp.ClientSession]] = None

        self.logger = logger

    @property
    def session(self):
        if not self._session:
            self._session = self._init_session()

        return self._session

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
                    "url": response.url,
                    "summary": summary,
                    "request_id": response.request_id,
                    "result": response.raw_result,
                }
            )
        )

        if status == ResponseStatus.VALIDATION_ERR.value:
            raise pe.ValidationException(summary, response)
        elif status == ResponseStatus.TOO_MANY_REQUESTS.value:
            raise pe.RateLimitException(summary, response)
        elif status == ResponseStatus.NO_CREDIT.value:
            raise pe.NoCreditException(summary, response)
        elif status == ResponseStatus.UNAUTHORIZED.value:
            raise pe.UnauthorizedException(self.service, response)
        elif status == ResponseStatus.SERVICE_NOT_ENABLED.value:
            raise pe.ServiceNotEnabledException(self.service, response)
        elif status == ResponseStatus.PROVIDER_ERR.value:
            raise pe.ProviderErrorException(summary, response)
        elif status in (ResponseStatus.MISSING_CONFIG_ID_SCOPE.value, ResponseStatus.MISSING_CONFIG_ID.value):
            raise pe.MissingConfigID(self.service, response)
        elif status == ResponseStatus.SERVICE_NOT_AVAILABLE.value:
            raise pe.ServiceNotAvailableException(summary, response)
        elif status == ResponseStatus.TREE_NOT_FOUND.value:
            raise pe.TreeNotFoundException(summary, response)
        elif status == ResponseStatus.IP_NOT_FOUND.value:
            raise pe.IPNotFoundException(summary)
        elif status == ResponseStatus.BAD_OFFSET.value:
            raise pe.BadOffsetException(summary, response)
        elif status == ResponseStatus.FORBIDDEN_VAULT_OPERATION.value:
            raise pe.ForbiddenVaultOperation(summary, response)
        elif status == ResponseStatus.VAULT_ITEM_NOT_FOUND.value:
            raise pe.VaultItemNotFound(summary, response)
        elif status == ResponseStatus.NOT_FOUND.value:
            raise pe.NotFound(response.raw_response.url if response.raw_response is not None else "", response)
        elif status == ResponseStatus.INTERNAL_SERVER_ERROR.value:
            raise pe.InternalServerError(response)
        elif status == ResponseStatus.ACCEPTED.value:
            raise pe.AcceptedRequestException(response)
        raise pe.PangeaAPIException(f"{summary} ", response)


class PangeaRequest(PangeaRequestBase):
    """An object that makes direct calls to Pangea Service APIs.

    Wraps Get/Post calls to support both API requests. If `queued_retry_enabled`
    is enabled, the progress of long running Post requests will queried until
    completion or until the `poll_result_timeout` is reached. Both values can
    be set in PangeaConfig.
    """

    def __del__(self):
        self.session.close()

    def post(
        self,
        endpoint: str,
        result_class: Type[PangeaResponseResult],
        data: Union[str, Dict] = {},
        files: Optional[List[Tuple]] = None,
        poll_result: bool = True,
        url: Optional[str] = None,
    ) -> PangeaResponse:
        """Makes the POST call to a Pangea Service endpoint.

        Args:
            endpoint(str): The Pangea Service API endpoint.
            data(dict): The POST body payload object

        Returns:
            PangeaResponse which contains the response in its entirety and
               various properties to retrieve individual fields
        """
        if url is None:
            url = self._url(endpoint)

        # Set config ID if available
        if self.config_id and data.get("config_id", None) is None:
            data["config_id"] = self.config_id

        if (
            files is not None
            and type(data) is dict
            and data.get("transfer_method", None) == TransferMethod.DIRECT.value
        ):
            requests_response = self._post_presigned_url(endpoint, result_class=result_class, data=data, files=files)
        else:
            requests_response = self._http_post(
                url, headers=self._headers(), data=data, files=files, multipart_post=True
            )

        pangea_response = PangeaResponse(requests_response, result_class=result_class, json=requests_response.json())
        if poll_result:
            pangea_response = self._handle_queued_result(pangea_response)

        return self._check_response(pangea_response)

    def _http_post(
        self,
        url: str,
        headers: Dict = {},
        data: Union[str, Dict] = {},
        files: Optional[List[Tuple]] = None,
        multipart_post: bool = True,
    ) -> requests.Response:
        self.logger.debug(
            json.dumps(
                {"service": self.service, "action": "http_post", "url": url, "data": data}, default=default_encoder
            )
        )

        data_send, files = self._http_post_process(data=data, files=files, multipart_post=multipart_post)
        return self.session.post(url, headers=headers, data=data_send, files=files)

    def _http_post_process(
        self, data: Union[str, Dict] = {}, files: Optional[List[Tuple]] = None, multipart_post: bool = True
    ):
        if files:
            if multipart_post is True:
                data_send = json.dumps(data, default=default_encoder) if isinstance(data, dict) else data
                multi = [("request", (None, data_send, "application/json"))]
                multi.extend(files)
                files = multi
                return None, files
            else:
                # Post to presigned url as form
                data_send = []
                for k, v in data.items():
                    data_send.append((k, v))
                # When posting to presigned url, file key should be 'file'
                files = {
                    "file": files[0][1],
                }
                return data_send, files
        else:
            data_send = json.dumps(data, default=default_encoder) if isinstance(data, dict) else data
            return data_send, None

        return data, files

    def _post_presigned_url(
        self,
        endpoint: str,
        result_class: Type[PangeaResponseResult],
        data: Union[str, Dict] = {},
        files: Optional[List[Tuple]] = None,
    ):
        if len(files) == 0:
            raise AttributeError("files attribute should have at least 1 file")

        # Send request
        try:
            # This should return 202 (AcceptedRequestException)
            resp = self.post(endpoint=endpoint, result_class=result_class, data=data, poll_result=False)
            raise pe.PresignedURLException("Should return 202", resp)

        except pe.AcceptedRequestException as e:
            accepted_exception = e
        except Exception as e:
            raise e

        # Receive 202 with accepted_status
        result = self._poll_presigned_url(accepted_exception)
        data_to_presigned = result.accepted_status.upload_details
        presigned_url = result.accepted_status.upload_url

        # Send multipart request with file and upload_details as body
        resp = self._http_post(url=presigned_url, data=data_to_presigned, files=files, multipart_post=False)
        self.logger.debug(
            json.dumps(
                {"service": self.service, "action": "post presigned", "url": presigned_url, "response": resp.text},
                default=default_encoder,
            )
        )

        if resp.status_code < 200 or resp.status_code >= 300:
            raise pe.PresignedUploadError(f"presigned POST failure: {resp.status_code}", resp.text)

        return accepted_exception.response.raw_response

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
        pangea_response = PangeaResponse(requests_response, result_class=result_class, json=requests_response.json())

        self.logger.debug(
            json.dumps(
                {"service": self.service, "action": "get", "url": url, "response": pangea_response.json},
                default=default_encoder,
            )
        )

        if check_response is False:
            return pangea_response

        return self._check_response(pangea_response)

    def poll_result_by_id(
        self, request_id: str, result_class: Union[Type[PangeaResponseResult], dict], check_response: bool = True
    ):
        path = self._get_poll_path(request_id)
        self.logger.debug(json.dumps({"service": self.service, "action": "poll_result_once", "url": path}))
        return self.get(path, result_class, check_response=check_response)

    def poll_result_once(self, response: PangeaResponse, check_response: bool = True):
        request_id = response.request_id
        if not request_id:
            raise pe.PangeaException("Poll result error: response did not include a 'request_id'")

        if response.status != ResponseStatus.ACCEPTED.value:
            raise pe.PangeaException("Response already proccesed")

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

    def _poll_presigned_url(self, initial_exc: pe.AcceptedRequestException) -> AcceptedResult:
        if type(initial_exc) is not pe.AcceptedRequestException:
            raise AttributeError("Exception should be of type AcceptedRequestException")

        if initial_exc.accepted_result.accepted_status.upload_url:
            return initial_exc.accepted_result

        self.logger.debug(json.dumps({"service": self.service, "action": "poll_presigned_url", "step": "start"}))
        retry_count = 1
        start = time.time()
        loop_exc = initial_exc

        while (
            loop_exc.accepted_result is not None
            and not loop_exc.accepted_result.accepted_status.upload_url
            and not self._reach_timeout(start)
        ):
            time.sleep(self._get_delay(retry_count, start))
            try:
                self.poll_result_once(initial_exc.response, check_response=False)
                msg = "Polling presigned url return 200 instead of 202"
                self.logger.debug(
                    json.dumps(
                        {"service": self.service, "action": "poll_presigned_url", "step": "exit", "cause": {msg}}
                    )
                )
                raise pe.PangeaException(msg)
            except pe.AcceptedRequestException as e:
                retry_count += 1
                loop_exc = e
            except Exception as e:
                self.logger.debug(
                    json.dumps(
                        {"service": self.service, "action": "poll_presigned_url", "step": "exit", "cause": {str(e)}}
                    )
                )
                raise pe.PresignedURLException("Failed to pull Presigned URL", loop_exc.response, e)

        self.logger.debug(json.dumps({"service": self.service, "action": "poll_presigned_url", "step": "exit"}))

        if loop_exc.accepted_result is not None and not loop_exc.accepted_result.accepted_status.upload_url:
            return loop_exc.accepted_result
        else:
            raise loop_exc

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

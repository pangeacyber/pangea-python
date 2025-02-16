# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from __future__ import annotations

import copy
import json
import logging
import time
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence, Tuple, Type, Union, cast

import requests
from pydantic import BaseModel
from pydantic_core import to_jsonable_python
from requests.adapters import HTTPAdapter, Retry
from requests_toolbelt import MultipartDecoder  # type: ignore[import-untyped]
from typing_extensions import TypeVar

import pangea
import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.response import AttachedFile, PangeaResponse, PangeaResponseResult, ResponseStatus, TransferMethod
from pangea.utils import default_encoder

if TYPE_CHECKING:
    import aiohttp


class MultipartResponse:
    pangea_json: Dict[str, str]
    attached_files: List = []

    def __init__(self, pangea_json: Dict[str, str], attached_files: List = []):
        self.pangea_json = pangea_json
        self.attached_files = attached_files


class PangeaRequestBase:
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
        self._extra_headers: Dict = {}
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

    def set_custom_user_agent(self, user_agent: Optional[str]):
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

    def _get_filename_from_content_disposition(self, content_disposition: str) -> Optional[str]:
        filename_parts = content_disposition.split("name=")
        if len(filename_parts) > 1:
            return filename_parts[1].split(";")[0].strip('"')
        return None

    def _get_filename_from_url(self, url: str) -> Optional[str]:
        return url.split("/")[-1].split("?")[0]

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
        if status == ResponseStatus.TOO_MANY_REQUESTS.value:
            raise pe.RateLimitException(summary, response)
        if status == ResponseStatus.NO_CREDIT.value:
            raise pe.NoCreditException(summary, response)
        if status == ResponseStatus.UNAUTHORIZED.value:
            raise pe.UnauthorizedException(self.service, response)
        if status == ResponseStatus.SERVICE_NOT_ENABLED.value:
            raise pe.ServiceNotEnabledException(self.service, response)
        if status == ResponseStatus.PROVIDER_ERR.value:
            raise pe.ProviderErrorException(summary, response)
        if status in (ResponseStatus.MISSING_CONFIG_ID_SCOPE.value, ResponseStatus.MISSING_CONFIG_ID.value):
            raise pe.MissingConfigID(self.service, response)
        if status == ResponseStatus.SERVICE_NOT_AVAILABLE.value:
            raise pe.ServiceNotAvailableException(summary, response)
        if status == ResponseStatus.TREE_NOT_FOUND.value:
            raise pe.TreeNotFoundException(summary, response)
        if status == ResponseStatus.IP_NOT_FOUND.value:
            raise pe.IPNotFoundException(summary, response)
        if status == ResponseStatus.BAD_OFFSET.value:
            raise pe.BadOffsetException(summary, response)
        if status == ResponseStatus.FORBIDDEN_VAULT_OPERATION.value:
            raise pe.ForbiddenVaultOperation(summary, response)
        if status == ResponseStatus.VAULT_ITEM_NOT_FOUND.value:
            raise pe.VaultItemNotFound(summary, response)
        if status == ResponseStatus.NOT_FOUND.value:
            raise pe.NotFound(str(response.raw_response.url) if response.raw_response is not None else "", response)
        if status == ResponseStatus.INTERNAL_SERVER_ERROR.value:
            raise pe.InternalServerError(response)
        if status == ResponseStatus.ACCEPTED.value:
            raise pe.AcceptedRequestException(response)
        raise pe.PangeaAPIException(f"{summary} ", response)


TResult = TypeVar("TResult", bound=PangeaResponseResult)


class PangeaRequest(PangeaRequestBase):
    """An object that makes direct calls to Pangea Service APIs.

    Wraps Get/Post calls to support both API requests. If `queued_retry_enabled`
    is enabled, the progress of long running Post requests will queried until
    completion or until the `poll_result_timeout` is reached. Both values can
    be set in PangeaConfig.
    """

    def __del__(self) -> None:
        self.session.close()

    def post(
        self,
        endpoint: str,
        result_class: Type[TResult],
        data: str | BaseModel | dict[str, Any] | None = None,
        files: Optional[List[Tuple]] = None,
        poll_result: bool = True,
        url: Optional[str] = None,
    ) -> PangeaResponse[TResult]:
        """Makes the POST call to a Pangea Service endpoint.

        Args:
            endpoint(str): The Pangea Service API endpoint.
            data(dict): The POST body payload object

        Returns:
            PangeaResponse which contains the response in its entirety and
               various properties to retrieve individual fields
        """

        if isinstance(data, BaseModel):
            data = data.model_dump(exclude_none=True)

        if isinstance(data, dict):
            # Remove `None` values.
            data = {k: v for k, v in data.items() if v is not None}

        if data is None:
            data = {}

        # Normalize.
        data = cast(dict[str, Any], to_jsonable_python(data))

        if url is None:
            url = self._url(endpoint)

        # Set config ID if available
        if self.config_id and isinstance(data, dict) and data.get("config_id", None) is None:
            data["config_id"] = self.config_id

        self.logger.debug(
            json.dumps({"service": self.service, "action": "post", "url": url, "data": data}, default=default_encoder)
        )
        transfer_method = data.get("transfer_method", None) if isinstance(data, dict) else None

        if files is not None and type(data) is dict and (transfer_method == TransferMethod.POST_URL.value):
            requests_response = self._full_post_presigned_url(
                endpoint, result_class=result_class, data=data, files=files
            )
        else:
            requests_response = self._http_post(
                url, headers=self._headers(), data=data, files=files, multipart_post=True
            )

        self._check_http_errors(requests_response)

        if "multipart/form-data" in requests_response.headers.get("content-type", ""):
            multipart_response = self._process_multipart_response(requests_response)
            pangea_response: PangeaResponse = PangeaResponse(
                requests_response,
                result_class=result_class,
                json=multipart_response.pangea_json,
                attached_files=multipart_response.attached_files,
            )
        else:
            try:
                json_resp = requests_response.json()
                self.logger.debug(
                    json.dumps({"service": self.service, "action": "post", "url": url, "response": json_resp})
                )

                pangea_response = PangeaResponse(requests_response, result_class=result_class, json=json_resp)
            except requests.exceptions.JSONDecodeError as e:
                raise pe.PangeaException(f"Failed to decode json response. {e}. Body: {requests_response.text}")

        if poll_result:
            pangea_response = self._handle_queued_result(pangea_response)

        return self._check_response(pangea_response)

    def _get_pangea_json(self, decoder: MultipartDecoder) -> Optional[Dict]:
        # Iterate through parts
        for i, part in enumerate(decoder.parts):
            if i == 0:
                json_str = part.content.decode("utf-8")
                return json.loads(json_str)

        return None

    def _get_attached_files(self, decoder: MultipartDecoder) -> List[AttachedFile]:
        files = []

        for i, part in enumerate(decoder.parts):
            content_type = part.headers.get(b"Content-Type", b"").decode("utf-8")
            # if "application/octet-stream" in content_type:
            if i > 0:
                content_disposition = part.headers.get(b"Content-Disposition", b"").decode("utf-8")
                name = self._get_filename_from_content_disposition(content_disposition)
                if name is None:
                    name = f"default_file_name_{i}"

                files.append(AttachedFile(name, part.content, content_type))

        return files

    def _process_multipart_response(self, resp: requests.Response) -> MultipartResponse:
        # Parse the multipart response
        decoder = MultipartDecoder.from_response(resp)

        pangea_json = self._get_pangea_json(decoder)
        self.logger.debug(
            json.dumps({"service": self.service, "action": "multipart response", "response": pangea_json})
        )

        attached_files = self._get_attached_files(decoder)
        return MultipartResponse(pangea_json, attached_files)  # type: ignore

    def _check_http_errors(self, resp: requests.Response):
        if resp.status_code == 503:
            raise pe.ServiceTemporarilyUnavailable(resp.json())

    def _http_post(
        self,
        url: str,
        headers: Dict = {},
        data: Union[str, Dict] = {},
        files: Optional[List[Tuple]] = None,
        multipart_post: bool = True,
    ) -> requests.Response:
        data_send, files = self._http_post_process(data=data, files=files, multipart_post=multipart_post)
        return self.session.post(url, headers=headers, data=data_send, files=files)

    def _http_post_process(
        self,
        data: Union[str, Dict] = {},
        files: Optional[Sequence[Tuple[str, Tuple[Any, str, str]]]] = None,
        multipart_post: bool = True,
    ):
        if files:
            if multipart_post is True:
                data_send: str = json.dumps(data, default=default_encoder) if isinstance(data, dict) else data
                multi = [("request", (None, data_send, "application/json"))]
                multi.extend(files)
                files = multi
                return None, files
            # Post to presigned url as form
            data_send: list = []  # type: ignore[no-redef]
            for k, v in data.items():  # type: ignore[union-attr]
                data_send.append((k, v))  # type: ignore[attr-defined]
            # When posting to presigned url, file key should be 'file'
            files = {  # type: ignore[assignment]
                "file": files[0][1],
            }
            return data_send, files
        data_send = json.dumps(data, default=default_encoder) if isinstance(data, dict) else data
        return data_send, None

        return data, files

    def _handle_queued_result(self, response: PangeaResponse[TResult]) -> PangeaResponse[TResult]:
        if self._queued_retry_enabled and response.http_status == 202:
            self.logger.debug(
                json.dumps(
                    {"service": self.service, "action": "poll_result", "response": response.json},
                    default=default_encoder,
                )
            )
            response = self._poll_result_retry(response)

        return response

    def get(self, path: str, result_class: Type[TResult], check_response: bool = True) -> PangeaResponse[TResult]:
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
        self._check_http_errors(requests_response)
        pangea_response: PangeaResponse = PangeaResponse(
            requests_response, result_class=result_class, json=requests_response.json()
        )

        self.logger.debug(
            json.dumps(
                {"service": self.service, "action": "get", "url": url, "response": pangea_response.json},
                default=default_encoder,
            )
        )

        if check_response is False:
            return pangea_response

        return self._check_response(pangea_response)

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

        self.logger.debug(
            json.dumps(
                {
                    "service": self.service,
                    "action": "download_file",
                    "url": url,
                    "filename": filename,
                    "status": "start",
                }
            )
        )
        response = self.session.get(url, headers={})
        if response.status_code == 200:
            if filename is None:
                content_disposition = response.headers.get(b"Content-Disposition", b"").decode("utf-8")
                filename = self._get_filename_from_content_disposition(content_disposition)
                if filename is None:
                    filename = self._get_filename_from_url(url)
                    if filename is None:
                        filename = "default_filename"

            content_type = response.headers.get(b"Content-Type", b"").decode("utf-8")

            self.logger.debug(
                json.dumps(
                    {
                        "service": self.service,
                        "action": "download_file",
                        "url": url,
                        "filename": filename,
                        "status": "success",
                    }
                )
            )
            return AttachedFile(filename=filename, file=response.content, content_type=content_type)
        raise pe.DownloadFileError(f"Failed to download file. Status: {response.status_code}", response.text)

    def poll_result_by_id(
        self, request_id: str, result_class: Type[TResult], check_response: bool = True
    ) -> PangeaResponse[TResult]:
        path = self._get_poll_path(request_id)
        self.logger.debug(json.dumps({"service": self.service, "action": "poll_result_once", "url": path}))
        return self.get(path, result_class, check_response=check_response)

    def poll_result_once(
        self, response: PangeaResponse[TResult], check_response: bool = True
    ) -> PangeaResponse[TResult]:
        request_id = response.request_id
        if not request_id:
            raise pe.PangeaException("Poll result error: response did not include a 'request_id'")

        if response.status != ResponseStatus.ACCEPTED.value:
            raise pe.PangeaException("Response already processed")

        return self.poll_result_by_id(request_id, response.result_class, check_response=check_response)

    def request_presigned_url(
        self,
        endpoint: str,
        result_class: Type[PangeaResponseResult],
        data: Union[str, Dict] = {},
    ) -> PangeaResponse:
        # Send request
        try:
            # This should return 202 (AcceptedRequestException) at least zero size file is sent
            return self.post(endpoint=endpoint, result_class=result_class, data=data, poll_result=False)
        except pe.AcceptedRequestException as e:
            accepted_exception = e
        except Exception as e:
            raise e

        # Receive 202
        return self._poll_presigned_url(accepted_exception.response)

    def post_presigned_url(self, url: str, data: Dict, files: List[Tuple]):
        # Send form request with file and upload_details as body
        resp = self._http_post(url=url, data=data, files=files, multipart_post=False)
        self.logger.debug(
            json.dumps(
                {"service": self.service, "action": "post presigned", "url": url, "response": resp.text},
                default=default_encoder,
            )
        )

        if resp.status_code < 200 or resp.status_code >= 300:
            raise pe.PresignedUploadError(f"presigned POST failure: {resp.status_code}", resp.text)

    def put_presigned_url(self, url: str, files: List[Tuple]):
        # Send put request with file as body
        resp = self._http_put(url=url, files=files)
        self.logger.debug(
            json.dumps(
                {"service": self.service, "action": "put presigned", "url": url, "response": resp.text},
                default=default_encoder,
            )
        )

        if resp.status_code < 200 or resp.status_code >= 300:
            raise pe.PresignedUploadError(f"presigned PUT failure: {resp.status_code}", resp.text)

    def _http_put(
        self,
        url: str,
        files: List[Tuple],
        headers: Dict = {},
    ) -> requests.Response:
        self.logger.debug(
            json.dumps({"service": self.service, "action": "http_put", "url": url}, default=default_encoder)
        )
        _, value = files[0]
        return self.session.put(url, headers=headers, data=value[1])

    def _full_post_presigned_url(
        self,
        endpoint: str,
        result_class: Type[PangeaResponseResult],
        data: Union[str, Dict] = {},
        files: Optional[List[Tuple]] = None,
    ):
        if files is None or len(files) == 0:
            raise AttributeError("files attribute should have at least 1 file")

        response = self.request_presigned_url(endpoint=endpoint, result_class=result_class, data=data)

        if response.success:  # This should only happen when uploading a zero bytes file
            return response.raw_response
        if response.accepted_result is None:
            raise pe.PangeaException("No accepted_result field when requesting presigned url")
        if response.accepted_result.post_url is None:
            raise pe.PresignedURLException("No presigned url", response)

        data_to_presigned = response.accepted_result.post_form_data
        presigned_url = response.accepted_result.post_url

        self.post_presigned_url(url=presigned_url, data=data_to_presigned, files=files)
        return response.raw_response

    def _poll_result_retry(self, response: PangeaResponse[TResult]) -> PangeaResponse[TResult]:
        retry_count = 1
        start = time.time()

        while response.status == ResponseStatus.ACCEPTED.value and not self._reach_timeout(start):
            time.sleep(self._get_delay(retry_count, start))
            response = self.poll_result_once(response, check_response=False)
            retry_count += 1

        self.logger.debug(json.dumps({"service": self.service, "action": "poll_result_retry", "step": "exit"}))
        return self._check_response(response)

    def _poll_presigned_url(self, response: PangeaResponse[TResult]) -> PangeaResponse[TResult]:
        if response.http_status != 202:
            raise AttributeError("Response should be 202")

        if response.accepted_result is not None and response.accepted_result.has_upload_url:
            return response

        self.logger.debug(json.dumps({"service": self.service, "action": "poll_presigned_url", "step": "start"}))
        retry_count = 1
        start = time.time()
        loop_resp = response

        while (
            loop_resp.accepted_result is not None
            and not loop_resp.accepted_result.has_upload_url
            and not self._reach_timeout(start)
        ):
            time.sleep(self._get_delay(retry_count, start))
            try:
                self.poll_result_once(loop_resp, check_response=False)
                msg = "Polling presigned url return 200 instead of 202"
                self.logger.debug(
                    json.dumps(
                        {"service": self.service, "action": "poll_presigned_url", "step": "exit", "cause": {msg}}
                    )
                )
                raise pe.PangeaException(msg)
            except pe.AcceptedRequestException as e:
                retry_count += 1
                loop_resp = e.response
                loop_exc = e
            except Exception as e:
                self.logger.debug(
                    json.dumps(
                        {"service": self.service, "action": "poll_presigned_url", "step": "exit", "cause": {str(e)}}
                    )
                )
                raise pe.PresignedURLException("Failed to pull Presigned URL", loop_resp, e)

        self.logger.debug(json.dumps({"service": self.service, "action": "poll_presigned_url", "step": "exit"}))

        if loop_resp.accepted_result is not None and not loop_resp.accepted_result.has_upload_url:
            return loop_resp
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

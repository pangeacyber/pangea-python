# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from __future__ import annotations

import asyncio
import json
import time
from typing import Dict, List, Optional, Sequence, Tuple, Type, Union, cast

import aiohttp
from aiohttp import FormData
from pydantic import BaseModel
from pydantic_core import to_jsonable_python
from typing_extensions import Any, TypeVar

import pangea.exceptions as pe
from pangea.request import MultipartResponse, PangeaRequestBase
from pangea.response import AttachedFile, PangeaResponse, PangeaResponseResult, ResponseStatus, TransferMethod
from pangea.utils import default_encoder

TResult = TypeVar("TResult", bound=PangeaResponseResult)


class PangeaRequestAsync(PangeaRequestBase):
    """An object that makes direct calls to Pangea Service APIs.

    Wraps Get/Post calls to support both API requests. If `queued_retry_enabled`
    is enabled, the progress of long running Post requests will queried until
    completion or until the `poll_result_timeout` is reached. Both values can
    be set in PangeaConfig.
    """

    async def post(
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
        if self.config_id and data.get("config_id", None) is None:
            data["config_id"] = self.config_id

        self.logger.debug(
            json.dumps({"service": self.service, "action": "post", "url": url, "data": data}, default=default_encoder)
        )
        transfer_method = data.get("transfer_method", None)

        if files and type(data) is dict and (transfer_method == TransferMethod.POST_URL.value):
            requests_response = await self._full_post_presigned_url(
                endpoint, result_class=result_class, data=data, files=files
            )
        else:
            requests_response = await self._http_post(
                url, headers=self._headers(), data=data, files=files, presigned_url_post=False
            )

        await self._check_http_errors(requests_response)

        if "multipart/form-data" in requests_response.headers.get("content-type", ""):
            multipart_response = await self._process_multipart_response(requests_response)
            pangea_response: PangeaResponse = PangeaResponse(
                requests_response,
                result_class=result_class,
                json=multipart_response.pangea_json,
                attached_files=multipart_response.attached_files,
            )
        else:
            try:
                json_resp = await requests_response.json()
                self.logger.debug(
                    json.dumps({"service": self.service, "action": "post", "url": url, "response": json_resp})
                )

                pangea_response = PangeaResponse(requests_response, result_class=result_class, json=json_resp)
            except aiohttp.ContentTypeError as e:
                raise pe.PangeaException(f"Failed to decode json response. {e}. Body: {await requests_response.text()}")

        if poll_result:
            pangea_response = await self._handle_queued_result(pangea_response)

        return self._check_response(pangea_response)

    async def get(self, path: str, result_class: Type[TResult], check_response: bool = True) -> PangeaResponse[TResult]:
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

        async with self.session.get(url, headers=self._headers()) as requests_response:
            await self._check_http_errors(requests_response)
            pangea_response = PangeaResponse(
                requests_response, result_class=result_class, json=await requests_response.json()
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

    async def _check_http_errors(self, resp: aiohttp.ClientResponse):
        if resp.status == 503:
            raise pe.ServiceTemporarilyUnavailable(await resp.json())

    async def poll_result_by_id(
        self, request_id: str, result_class: Type[TResult], check_response: bool = True
    ) -> PangeaResponse[TResult]:
        path = self._get_poll_path(request_id)
        self.logger.debug(json.dumps({"service": self.service, "action": "poll_result_once", "url": path}))
        return await self.get(path, result_class, check_response=check_response)

    async def poll_result_once(self, response: PangeaResponse, check_response: bool = True):
        request_id = response.request_id
        if not request_id:
            raise pe.PangeaException("Poll result error error: response did not include a 'request_id'")

        if response.status != ResponseStatus.ACCEPTED.value:
            raise pe.PangeaException("Response already proccesed")

        return await self.poll_result_by_id(request_id, response.result_class, check_response=check_response)

    async def post_presigned_url(self, url: str, data: Dict, files: List[Tuple]):
        # Send form request with file and upload_details as body
        resp = await self._http_post(url=url, data=data, files=files, presigned_url_post=True)
        self.logger.debug(
            json.dumps(
                {"service": self.service, "action": "post presigned", "url": url, "response": await resp.text()},
                default=default_encoder,
            )
        )

        if resp.status < 200 or resp.status >= 300:
            raise pe.PresignedUploadError(f"presigned POST failure: {resp.status}", await resp.text())

    async def put_presigned_url(self, url: str, files: Sequence[Tuple]):
        # Send put request with file as body
        resp = await self._http_put(url=url, files=files)
        self.logger.debug(
            json.dumps(
                {"service": self.service, "action": "put presigned", "url": url, "response": await resp.text()},
                default=default_encoder,
            )
        )

        if resp.status < 200 or resp.status >= 300:
            raise pe.PresignedUploadError(f"presigned PUT failure: {resp.status}", await resp.text())

    async def download_file(self, url: str, filename: str | None = None) -> AttachedFile:
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
        async with self.session.get(url, headers={}) as response:
            if response.status == 200:
                if filename is None:
                    content_disposition = response.headers.get("Content-Disposition", "")
                    filename = self._get_filename_from_content_disposition(content_disposition)
                    if filename is None:
                        filename = self._get_filename_from_url(url)
                        if filename is None:
                            filename = "default_filename"

                content_type = response.headers.get("Content-Type", "")
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

                return AttachedFile(filename=filename, file=await response.read(), content_type=content_type)
            raise pe.DownloadFileError(f"Failed to download file. Status: {response.status}", await response.text())

    async def _get_pangea_json(self, reader: aiohttp.multipart.MultipartResponseWrapper) -> Optional[Dict[str, Any]]:
        # Iterate through parts
        async for part in reader:
            if isinstance(part, aiohttp.BodyPartReader):
                return await part.json()
        return None

    async def _get_attached_files(self, reader: aiohttp.multipart.MultipartResponseWrapper) -> List[AttachedFile]:
        files = []
        i = 0

        async for part in reader:
            content_type = part.headers.get("Content-Type", "")
            content_disposition = part.headers.get("Content-Disposition", "")
            name = self._get_filename_from_content_disposition(content_disposition)
            if name is None:
                name = f"default_file_name_{i}"
                i += 1
            files.append(AttachedFile(name, await part.read(), content_type))  # type: ignore[union-attr]

        return files

    async def _process_multipart_response(self, resp: aiohttp.ClientResponse) -> MultipartResponse:
        # Parse the multipart response
        multipart_reader = aiohttp.MultipartReader.from_response(resp)

        pangea_json = await self._get_pangea_json(multipart_reader)
        self.logger.debug(
            json.dumps({"service": self.service, "action": "multipart response", "response": pangea_json})
        )

        attached_files = await self._get_attached_files(multipart_reader)
        return MultipartResponse(pangea_json, attached_files)  # type: ignore[arg-type]

    async def _http_post(
        self,
        url: str,
        headers: Dict = {},
        data: Union[str, Dict] = {},
        files: Optional[List[Tuple]] = [],
        presigned_url_post: bool = False,
    ) -> aiohttp.ClientResponse:
        if files:
            form = FormData()
            if presigned_url_post:
                for k, v in data.items():  # type: ignore[union-attr]
                    form.add_field(k, v)
                for name, value in files:
                    form.add_field("file", value[1], filename=value[0], content_type=value[2])
            else:
                data_send = json.dumps(data, default=default_encoder) if isinstance(data, dict) else data
                form.add_field("request", data_send, content_type="application/json")
                for name, value in files:
                    form.add_field(name, value[1], filename=value[0], content_type=value[2])

            data_send = form  # type: ignore[assignment]
        else:
            data_send = json.dumps(data, default=default_encoder) if isinstance(data, dict) else data

        return await self.session.post(url, headers=headers, data=data_send)

    async def _http_put(
        self,
        url: str,
        files: Sequence[Tuple],
        headers: Dict = {},
    ) -> aiohttp.ClientResponse:
        self.logger.debug(
            json.dumps({"service": self.service, "action": "http_put", "url": url}, default=default_encoder)
        )
        _, value = files[0]
        return await self.session.put(url, headers=headers, data=value[1])

    async def _full_post_presigned_url(
        self,
        endpoint: str,
        result_class: Type[PangeaResponseResult],
        data: Union[str, Dict] = {},
        files: List[Tuple] = [],
    ):
        if len(files) == 0:
            raise AttributeError("files attribute should have at least 1 file")

        response = await self.request_presigned_url(endpoint=endpoint, result_class=result_class, data=data)
        if response.success:  # This should only happen when uploading a zero bytes file
            return response.raw_response

        if response.accepted_result is None:
            raise pe.PangeaException("No accepted_result field when requesting presigned url")
        if response.accepted_result.post_url is None:
            raise pe.PresignedURLException("No presigned url", response)

        data_to_presigned = response.accepted_result.post_form_data
        presigned_url = response.accepted_result.post_url

        await self.post_presigned_url(url=presigned_url, data=data_to_presigned, files=files)
        return response.raw_response

    async def request_presigned_url(
        self,
        endpoint: str,
        result_class: Type[PangeaResponseResult],
        data: Union[str, Dict] = {},
    ) -> PangeaResponse:
        # Send request
        try:
            # This should return 202 (AcceptedRequestException) at least zero size file is sent
            return await self.post(endpoint=endpoint, result_class=result_class, data=data, poll_result=False)
        except pe.AcceptedRequestException as e:
            accepted_exception = e
        except Exception as e:
            raise e

        # Receive 202
        return await self._poll_presigned_url(accepted_exception.response)

    async def _poll_presigned_url(self, response: PangeaResponse[TResult]) -> PangeaResponse[TResult]:
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
            await asyncio.sleep(self._get_delay(retry_count, start))
            try:
                await self.poll_result_once(response, check_response=False)
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
                raise pe.PresignedURLException("Failed to pull Presigned URL", loop_exc.response, e)

        self.logger.debug(json.dumps({"service": self.service, "action": "poll_presigned_url", "step": "exit"}))

        if loop_resp.accepted_result is not None and not loop_resp.accepted_result.has_upload_url:
            return loop_resp
        raise loop_exc

    async def _handle_queued_result(self, response: PangeaResponse) -> PangeaResponse:
        if self._queued_retry_enabled and response.http_status == 202:
            self.logger.debug(
                json.dumps(
                    {"service": self.service, "action": "poll_result", "response": response.json},
                    default=default_encoder,
                )
            )
            response = await self._poll_result_retry(response)

        return response

    async def _poll_result_retry(self, response: PangeaResponse) -> PangeaResponse:
        retry_count = 1
        start = time.time()

        while response.status == ResponseStatus.ACCEPTED.value and not self._reach_timeout(start):
            await asyncio.sleep(self._get_delay(retry_count, start))
            response = await self.poll_result_once(response, check_response=False)
            retry_count += 1

        self.logger.debug(json.dumps({"service": self.service, "action": "poll_result_retry", "step": "exit"}))
        return self._check_response(response)

    def _init_session(self) -> aiohttp.ClientSession:
        # retry_config = Retry(
        #     total=self.config.request_retries,
        #     backoff_factor=self.config.request_backoff,
        #     status_forcelist=[500, 502, 503, 504],
        # )
        # adapter = HTTPAdapter(max_retries=retry_config)
        # TODO: Add retry config

        session = aiohttp.ClientSession()
        return session

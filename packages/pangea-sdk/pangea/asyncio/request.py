# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import asyncio
import json
import time
from typing import Dict, List, Optional, Tuple, Type, Union

import aiohttp
import pangea.exceptions as pe
from aiohttp import FormData

# from requests.adapters import HTTPAdapter, Retry
from pangea.request import PangeaRequestBase
from pangea.response import AcceptedResult, PangeaResponse, PangeaResponseResult, ResponseStatus, TransferMethod
from pangea.utils import default_encoder


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
            requests_response = await self._post_presigned_url(
                endpoint, result_class=result_class, data=data, files=files
            )
        else:
            requests_response = await self._http_post(
                url, headers=self._headers(), data=data, files=files, presigned_url_post=False
            )

        pangea_response = PangeaResponse(
            requests_response, result_class=result_class, json=await requests_response.json()
        )
        if poll_result:
            pangea_response = await self._handle_queued_result(pangea_response)

        return self._check_response(pangea_response)

    async def _http_post(
        self,
        url: str,
        headers: Dict = {},
        data: Union[str, Dict] = {},
        files: Optional[List[Tuple]] = None,
        presigned_url_post: bool = False,
    ) -> aiohttp.ClientResponse:
        self.logger.debug(
            json.dumps(
                {"service": self.service, "action": "http_post", "url": url, "data": data}, default=default_encoder
            )
        )

        if files:
            form = FormData()
            if presigned_url_post:
                for k, v in data.items():
                    form.add_field(k, v)
                for name, value in files:
                    form.add_field("file", value[1], filename=value[0], content_type=value[2])
            else:
                data_send = json.dumps(data, default=default_encoder) if isinstance(data, dict) else data
                form.add_field("request", data_send, content_type="application/json")
                for name, value in files:
                    form.add_field(name, value[1], filename=value[0], content_type=value[2])

            data_send = form
        else:
            data_send = json.dumps(data, default=default_encoder) if isinstance(data, dict) else data

        return await self.session.post(url, headers=headers, data=data_send)

    async def _post_presigned_url(
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
            resp = await self.post(endpoint=endpoint, result_class=result_class, data=data, poll_result=False)
            raise pe.PresignedURLException("Should return 202", resp)

        except pe.AcceptedRequestException as e:
            accepted_exception = e
        except Exception as e:
            raise e

        # Receive 202 with accepted_status
        result = await self._poll_presigned_url(accepted_exception)
        data_to_presigned = result.accepted_status.upload_details
        presigned_url = result.accepted_status.upload_url

        # Send multipart request with file and upload_details as body
        resp = await self._http_post(url=presigned_url, data=data_to_presigned, files=files, presigned_url_post=True)
        self.logger.debug(
            json.dumps(
                {
                    "service": self.service,
                    "action": "post presigned",
                    "url": presigned_url,
                    "response": await resp.text(),
                },
                default=default_encoder,
            )
        )

        if resp.status < 200 or resp.status >= 300:
            raise pe.PresignedUploadError(f"presigned POST failure: {resp.status}", await resp.text())

        return accepted_exception.response.raw_response

    async def _poll_presigned_url(self, initial_exc: pe.AcceptedRequestException) -> AcceptedResult:
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
            await asyncio.sleep(self._get_delay(retry_count, start))
            try:
                await self.poll_result_once(initial_exc.response, check_response=False)
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

    async def get(
        self, path: str, result_class: Type[PangeaResponseResult], check_response: bool = True
    ) -> PangeaResponse:
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

    async def poll_result_by_id(
        self, request_id: str, result_class: Union[Type[PangeaResponseResult], dict], check_response: bool = True
    ):
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

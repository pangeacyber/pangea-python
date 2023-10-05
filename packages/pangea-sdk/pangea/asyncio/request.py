# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import asyncio
import json
import time
from typing import Dict, List, Optional, Tuple, Type, Union

import aiohttp
from aiohttp import FormData
from pangea import exceptions

# from requests.adapters import HTTPAdapter, Retry
from pangea.request import PangeaRequestBase
from pangea.response import PangeaResponse, PangeaResponseResult, ResponseStatus
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

        # FIXME: use FormData to send multipart request
        if files:
            form = FormData()
            form.add_field("request", data_send, content_type="application/json")
            for name, value in files:
                # [("upload", ("filename.exe", file, "application/octet-stream"))]
                form.add_field(name, value[1], filename=value[0], content_type=value[2])

            data_send = form

        async with self.session.post(url, headers=self._headers(), data=data_send) as requests_response:
            pangea_response = PangeaResponse(
                requests_response, result_class=result_class, json=await requests_response.json()
            )

        if poll_result:
            pangea_response = await self._handle_queued_result(pangea_response)

        self.logger.debug(
            json.dumps(
                {"service": self.service, "action": "post", "url": url, "response": pangea_response.json},
                default=default_encoder,
            )
        )
        return self._check_response(pangea_response)

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
            raise exceptions.PangeaException("Poll result error error: response did not include a 'request_id'")

        if response.status != ResponseStatus.ACCEPTED.value:
            raise exceptions.PangeaException("Response already proccesed")

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

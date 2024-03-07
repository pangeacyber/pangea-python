# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from typing import Dict, Optional, Type, Union

from pangea.asyncio.request import PangeaRequestAsync
from pangea.exceptions import AcceptedRequestException
from pangea.response import AttachedFile, PangeaResponse, PangeaResponseResult
from pangea.services.base import PangeaRequest, ServiceBase


class ServiceBaseAsync(ServiceBase):
    @property
    def request(self) -> PangeaRequestAsync:  # type: ignore[override]
        if self._request is None or isinstance(self._request, PangeaRequest):
            self._request = PangeaRequestAsync(
                config=self.config,
                token=self.token,
                service=self.service_name,
                logger=self.logger,
                config_id=self.config_id,
            )

        return self._request

    async def poll_result(  # type: ignore[override]
        self,
        exception: Optional[AcceptedRequestException] = None,
        response: Optional[PangeaResponse] = None,
        request_id: Optional[str] = None,
        result_class: Union[Type[PangeaResponseResult], Type[Dict]] = dict,
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
            return await self.request.poll_result_once(exception.response, check_response=True)
        elif response is not None:
            return await self.request.poll_result_once(response, check_response=True)
        elif request_id is not None:
            return await self.request.poll_result_by_id(
                request_id=request_id, result_class=result_class, check_response=True
            )
        else:
            raise AttributeError("Need to set exception, response or request_id")

    async def download_file(self, url: str, filename: Optional[str] = None) -> AttachedFile:  # type: ignore[override]
        return await self.request.download_file(url=url, filename=filename)

    async def close(self):
        await self.request.session.close()
        # Loop over all attributes to check if they are derived from ServiceBaseAsync and close them
        for _, value in self.__dict__.items():
            if issubclass(type(value), ServiceBaseAsync):
                await value.close()

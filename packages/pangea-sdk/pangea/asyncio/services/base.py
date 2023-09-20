# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from pangea.asyncio.request import PangeaRequestAsync
from pangea.exceptions import AcceptedRequestException
from pangea.response import PangeaResponse
from pangea.services.base import ServiceBase


class ServiceBaseAsync(ServiceBase):
    @property
    def request(self):
        if not self._request:
            self._request = PangeaRequestAsync(
                config=self.config,
                token=self.token,
                service=self.service_name,
                logger=self.logger,
                config_id=self.config_id,
            )

        return self._request

    async def poll_result(self, exception: AcceptedRequestException) -> PangeaResponse:
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
        return await self.request.poll_result_once(exception.response, check_response=True)

    async def close(self):
        await self.request.session.close()
        # Loop over all attributes to check if they are derived from ServiceBaseAsync and close them
        for _, value in self.__dict__.items():
            if issubclass(type(value), ServiceBaseAsync):
                await value.close()

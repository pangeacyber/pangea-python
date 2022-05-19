# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from .base import ServiceBase


class Tester(ServiceBase):
    service_name = "tester"
    version = ""

    def async_call(self, data: dict):
        endpoint_name = "go/pri/test"

        response = self.request.post(endpoint_name, data=data)

        return response

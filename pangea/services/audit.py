# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import json
from pangea.response import PangeaResponse
from .base import ServiceBase

SupportedFields = [
    "actor",
    "action",
    "message",
    "status",
    "source",
    "target",
]

SupportedJSONFields = [
    "new",
    "old",
]


class AuditSearchResponse(object):
    """
    Wrap the base Response object to include search pagination support
    """

    def __init__(self, response, data):
        self.response = response
        self.data = data

    def __getattr__(self, attr):
        return getattr(self.response, attr)

    def next(self):
        if self.count < self.total:
            params = {
                "query": self.data["query"],
                "last": self.result.last,
                "size": self.data["max_results"],
            }

            if hasattr(self.data, "start"):
                params.update({"start": self.data["start"]})

            if hasattr(self.data, "end"):
                params.update({"end": self.data["end"]})

            return params
        else:
            return None

    @property
    def total(self) -> str:
        if self.success:
            last = self.result.last
            total = last.split("|")[1]  # TODO: update once `last` returns an object
            return int(total)
        else:
            return 0

    @property
    def count(self) -> str:
        if self.success:
            last = self.result.last
            count = last.split("|")[0]  # TODO: update once `last` returns an object
            return int(count)
        else:
            return 0


class Audit(ServiceBase):
    response_class = AuditSearchResponse
    service_name = "audit"
    version = "v1"

    def log(self, message: dict, source: str = "") -> PangeaResponse:
        endpoint_name = "log"

        """
        Filter input on valid field params, at least one valid param is required
        """
        data = {}

        for name in SupportedFields:
            if name in message:
                data[name] = message[name]

        for name in SupportedJSONFields:
            if name in message:
                data[name] = json.dumps(message[name])

        if "message" not in data:
            raise Exception(f"Error: missing required field, no `message` provided")

        response = self.request.post(endpoint_name, data=data)

        return response

    def search(
        self,
        query: str = "",
        sources: list = [],
        size: int = 20,
        start: str = "",
        end: str = "",
        last: str = "",
    ) -> AuditSearchResponse:
        endpoint_name = "search"

        """
        The `size` param determines the maximum results returned, it must be a positive integer.
        """
        if not (isinstance(size, int) and size > 0):
            raise Exception("The 'size' argument must be a positive integer > 0")

        data = {"query": query, "max_results": size}

        if start:
            # TODO: validate start date/duration format
            data.update({"start": start})

        if end:
            # TODO: validate end date/duration format
            data.update({"end": end})

        if last:
            data.update({"last": last})

        if sources:
            data.update({"sources": sources})

        response = self.request.post(endpoint_name, data=data)

        response_wrapper = AuditSearchResponse(response, data)

        return response_wrapper

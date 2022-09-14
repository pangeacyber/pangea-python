# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import enum
from typing import Any, Dict, Generic, Optional, TypeVar

import requests
from pydantic import BaseModel
from pydantic.dataclasses import dataclass


class JSONObject(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for k, v in self.items():
            k = k.replace(".", "_")
            setattr(self, k, self.compute_attr_value(v))

    def compute_attr_value(self, value):
        if isinstance(value, list):
            return [self.compute_attr_value(x) for x in value]
        elif isinstance(value, dict):
            return JSONObject(value)
        else:
            return value

    def __getattr__(self, name: str):
        return self.get(name)

    def __setattr__(self, name: str, value) -> None:
        self[name] = value


class DataclassConfig:
    arbitrary_types_allowed = True
    extra = "ignore"


T = TypeVar("T")


class BaseModelConfig(BaseModel):
    class Config:
        arbitrary_types_allowed = True


class ResponseStatus(str, enum.Enum):
    SUCCESS = "Success"
    FAILED = "Failed"


class ResponseHeader(BaseModelConfig):
    """
    TODO: complete

    Arguments:
    request_id -- The request ID.
    request_time -- The time the request was issued, ISO8601.
    response_time -- The time the response was issued, ISO8601.
    status -- The HTTP status code msg.
    summary -- The summary of the response.
    """

    request_id: str
    request_time: str
    response_time: str
    status: str
    summary: str


class PangeaResponse(Generic[T], ResponseHeader):
    status_code: Optional[int] = None
    raw_result: Optional[Dict[str, Any] | str] = None
    raw_response: Optional[requests.Response] = None
    result: Optional[T] = None

    def __init__(self, response: requests.Response):
        json = response.json()
        super(PangeaResponse, self).__init__(**json)
        self.status_code = response.status_code
        self.raw_response = response
        self.raw_result = json["result"]
        self.result = T(**json["result"]) if callable(T) else json["result"]

    @property
    def success(self) -> bool:
        return self.status == "Success"


# class PangeaResponse(Generic[T], object):
#     """An object containing Pangea Service API response.

#     Properties:
#         result (T): "result" field of the API response as documented at:
#             [https://docs.dev.pangea.cloud/docs/api/#responses](https://docs.dev.pangea.cloud/docs/api/#responses)
#         status (str): Pangea status code
#         status_code(int): HTTP Status Code
#         success (bool): true if call was successful
#         request_id (str): the ID of the request as tracked by Pangea
#         response (obj): the entire API response payload
#         FIXME: complete docs
#     """

#     def __init__(self, requests_response: requests.Response):
#         data = requests_response.json()
#         status = data["status"]
#         self._status = status
#         self._data = JSONObject(data)
#         self._success = status == "Success"
#         self._response = requests_response
#         self._status_code = requests_response.status_code
#         self._result: Optional[T | str] = None
#         if self._success:
#             self._result = T(**data["result"])
#         else:
#             self._result = data["result"]


#     @property
#     def data(self) -> JSONObject:
#         return self._data

#     @property
#     def result(self) -> Optional[T]:
#         return self._result

#     @property
#     def status(self) -> str:
#         return self._status

#     @property
#     def success(self) -> bool:
#         return self._success

#     @property
#     def request_id(self) -> Optional[str]:
#         return self._data.get("request_id", None)

#     @property
#     def response(self) -> requests.Response:
#         return self._response

#     @property
#     def code(self) -> int:
#         return self._status_code

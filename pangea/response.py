# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import enum
from typing import Any, Dict, Generic, List, Optional, TypeVar, Union

import requests
from pydantic import BaseModel


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


class ErrorField(BaseModelConfig):
    """
    Field errors denote errors in fields provided in request payloads

    Fields:
        code(str): The field code
        detail(str): A human readable detail explaining the error
        source(str): A JSON pointer where the error occurred
        path(str): If verbose mode was enabled, a path to the JSON Schema used
            to validate the field
    """

    code: str
    detail: str
    source: str
    path: Optional[str] = None


class PangeaError(BaseModelConfig):
    errors: List[ErrorField] = []


class PangeaResponseResult(BaseModelConfig):
    pass


class ResponseStatus(str, enum.Enum):
    SUCCESS = "Success"
    FAILED = "Failed"
    VALIDATION_ERR = "ValidationError"
    TOO_MANY_REQUESTS = "TooManyRequests"
    NO_CREDIT = "NoCredit"
    UNAUTHORIZED = "Unauthorized"
    SERVICE_NOT_ENABLED = "ServiceNotEnabled"
    PROVIDER_ERR = "ProviderError"
    MISSING_CONFIG_ID_SCOPE = "MissingConfigIDScope"
    MISSING_CONFIG_ID = "MissingConfigID"
    SERVICE_NOT_AVAILABLE = "ServiceNotAvailable"
    TREE_NOT_FOUND = "TreeNotFound"
    IP_NOT_FOUND = "IPNotFound"


class ResponseHeader(BaseModelConfig):
    """
    TODO: complete

    Arguments:
    request_id -- The request ID.
    request_time -- The time the request was issued, ISO8601.
    response_time -- The time the response was issued, ISO8601.
    status -- Pangea response status
    summary -- The summary of the response.
    """

    request_id: str
    request_time: str
    response_time: str
    status: str
    summary: str


class PangeaResponse(Generic[T], ResponseHeader):
    raw_result: Optional[Dict[str, Any]] = None
    raw_response: Optional[requests.Response] = None
    result: Optional[T] = None
    errors: Optional[PangeaError] = None

    def __init__(self, response: requests.Response):
        json = response.json()
        super(PangeaResponse, self).__init__(**json)
        self.raw_response = response
        self.raw_result = json["result"]
        self.result = (
            T(**json["result"])
            if issubclass(type(T), PangeaResponseResult) and self.status == ResponseStatus.SUCCESS.value
            else None
        )

    @property
    def success(self) -> bool:
        return self.status == "Success"

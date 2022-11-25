# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import enum
from typing import Any, Dict, Generic, List, Optional, TypeVar

import requests
from pydantic import BaseModel

T = TypeVar("T")


# API response should accept arbitrary fields to make them accept possible new parameters
class APIResponseModel(BaseModel):
    class Config:
        arbitrary_types_allowed = True
        # allow parameters despite they are not declared in model. Make SDK accept server new parameters
        extra = "allow"


# API request models doesn't not allow arbitrary fields
class APIRequestModel(BaseModel):
    class Config:
        arbitrary_types_allowed = True


class PangeaResponseResult(APIResponseModel):
    pass


class ErrorField(PangeaResponseResult):
    """
    Field errors denote errors in fields provided in request payloads

    Fields:
        code(str): The field code
        detail(str): A human readable detail explaining the error
        source(str): A JSON pointer where the error occurred
        path(str): If verbose mode was enabled, a path to the JSON Schema used to validate the field
    """

    code: str
    detail: str
    source: str
    path: Optional[str] = None


class PangeaError(PangeaResponseResult):
    errors: List[ErrorField] = []


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
    BAD_OFFSET = "BadOffset"


class ResponseHeader(APIResponseModel):
    """
    Pangea response API header.

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
    pangea_error: Optional[PangeaError] = None

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
        if not self.success:
            self.pangea_error = PangeaError(**self.raw_result) if self.raw_result is not None else None

    @property
    def success(self) -> bool:
        return self.status == ResponseStatus.SUCCESS.value

    @property
    def errors(self) -> List[ErrorField]:
        return self.pangea_error.errors if self.pangea_error is not None else []

# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import datetime
import enum
from typing import Any, Dict, Generic, List, Optional, Type, TypeVar, Union

import aiohttp
import requests
from pangea.utils import format_datetime
from pydantic import BaseModel

T = TypeVar("T")


class TransferMethod(str, enum.Enum):
    DIRECT = "direct"
    MULTIPART = "multipart"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


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
        extra = (
            "allow"  # allow parameters despite they are not declared in model. Make SDK accept server new parameters
        )
        json_encoders = {
            datetime.datetime: format_datetime,
        }


class PangeaResponseResult(APIResponseModel):
    pass


class ErrorField(APIResponseModel):
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

    def __repr__(self):
        return f"{self.source} {self.code}: {self.detail}."

    def __str__(self) -> str:
        return self.__repr__()


class AcceptedStatus(APIResponseModel):
    upload_url: str = ""
    upload_details: Dict[str, Any] = {}


class AcceptedResult(PangeaResponseResult):
    accepted_status: AcceptedStatus


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
    FORBIDDEN_VAULT_OPERATION = "ForbiddenVaultOperation"
    VAULT_ITEM_NOT_FOUND = "VaultItemNotFound"
    NOT_FOUND = "NotFound"
    INTERNAL_SERVER_ERROR = "InternalError"
    ACCEPTED = "Accepted"


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
    raw_response: Optional[Union[requests.Response, aiohttp.ClientResponse]] = None
    result: Optional[T] = None
    pangea_error: Optional[PangeaError] = None
    accepted_result: Optional[AcceptedResult] = None
    result_class: Type[PangeaResponseResult] = PangeaResponseResult
    _json: Any

    def __init__(self, response: requests.Response, result_class: Type[PangeaResponseResult], json: dict):
        super(PangeaResponse, self).__init__(**json)
        self._json = json
        self.raw_response = response
        self.raw_result = self._json["result"]
        self.result_class = result_class
        self.result = (
            self.result_class(**self.raw_result)
            if self.raw_result is not None and issubclass(self.result_class, PangeaResponseResult) and self.success
            else None
        )
        if not self.success and self.http_status != 202:
            self.pangea_error = PangeaError(**self.raw_result) if self.raw_result is not None else None

    @property
    def success(self) -> bool:
        return self.status == ResponseStatus.SUCCESS.value

    @property
    def errors(self) -> List[ErrorField]:
        return self.pangea_error.errors if self.pangea_error is not None else []

    @property
    def json(self) -> Any:
        return self._json

    @property
    def http_status(self) -> int:
        if self.raw_response:
            if type(self.raw_response) == aiohttp.ClientResponse:
                return self.raw_response.status
            else:
                return self.raw_response.status_code

    @property
    def url(self) -> str:
        return str(self.raw_response.url)

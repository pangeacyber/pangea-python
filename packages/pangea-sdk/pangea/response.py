# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import datetime
import enum
import os
from typing import Any, Dict, Generic, List, Optional, Type, Union

import aiohttp
import requests
from pydantic import BaseModel, ConfigDict, PlainSerializer
from typing_extensions import Annotated, TypeVar

from pangea.utils import format_datetime


class AttachedFile(object):
    filename: str
    file: bytes
    content_type: str

    def __init__(self, filename: str, file: bytes, content_type: str):
        self.filename = filename
        self.file = file
        self.content_type = content_type

    def save(self, dest_folder: str = "./", filename: Optional[str] = None):
        if filename is None:
            filename = self.filename if self.filename else "default_save_filename"

        filepath = os.path.join(dest_folder, filename)
        filepath = self._find_available_file(filepath)
        directory = os.path.dirname(filepath)
        if not os.path.exists(directory):
            os.makedirs(directory)

        with open(filepath, "wb") as file:
            file.write(self.file)

    def _find_available_file(self, file_path):
        base_name, ext = os.path.splitext(file_path)
        counter = 1
        while os.path.exists(file_path):
            if ext:
                file_path = f"{base_name}_{counter}{ext}"
            else:
                file_path = f"{base_name}_{counter}"
            counter += 1
        return file_path


class TransferMethod(str, enum.Enum):
    """Transfer methods for uploading file data."""

    MULTIPART = "multipart"
    POST_URL = "post-url"
    PUT_URL = "put-url"
    SOURCE_URL = "source-url"
    """
    A `source-url` is a caller-specified URL where the Pangea APIs can fetch the
    contents of the input file. When calling a Pangea API with a
    `transfer_method` of `source-url`, you must also specify a `source_url`
    input parameter that provides a URL to the input file. The source URL can be
    a presigned URL created by the caller, and it will be used to download the
    content of the input file. The `source-url` transfer method is useful when
    you already have a file in your storage and can provide a URL from which
    Pangea API can fetch the input file—there is no need to transfer it to
    Pangea with a separate POST or PUT request.
    """

    DEST_URL = "dest-url"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


PangeaDateTime = Annotated[datetime.datetime, PlainSerializer(format_datetime)]


# API response should accept arbitrary fields to make them accept possible new parameters
class APIResponseModel(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")


# API request models doesn't not allow arbitrary fields
class APIRequestModel(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")


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
    ttl_mins: int
    retry_counter: int
    location: str
    post_url: Optional[str] = None
    post_form_data: Dict[str, Any] = {}
    put_url: Optional[str] = None

    @property
    def has_upload_url(self) -> bool:
        return self.post_url is not None or self.put_url is not None


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
    """Pangea response API header."""

    request_id: str
    """A unique identifier assigned to each request made to the API."""

    request_time: str
    """
    Timestamp indicating the exact moment when a request is made to the API.
    """

    response_time: str
    """
    Duration it takes for the API to process a request and generate a response.
    """

    status: str
    """
    Represents the status or outcome of the API request.
    """

    summary: str
    """
    Provides a concise and brief overview of the purpose or primary objective of
    the API endpoint.
    """


T = TypeVar("T", bound=PangeaResponseResult)


class PangeaResponse(ResponseHeader, Generic[T]):
    raw_result: Optional[Dict[str, Any]] = None
    raw_response: Optional[Union[requests.Response, aiohttp.ClientResponse]] = None
    result: Optional[T] = None
    pangea_error: Optional[PangeaError] = None
    accepted_result: Optional[AcceptedResult] = None
    result_class: Type[T] = PangeaResponseResult  # type: ignore[assignment]
    _json: Any
    attached_files: List[AttachedFile] = []

    def __init__(
        self,
        response: requests.Response,
        result_class: Type[T],
        json: dict,
        attached_files: List[AttachedFile] = [],
    ):
        super(PangeaResponse, self).__init__(**json)
        self._json = json
        self.raw_response = response
        self.raw_result = self._json["result"]
        self.result_class = result_class
        self.attached_files = attached_files

        self.result = (
            self.result_class(**self.raw_result)
            if self.raw_result is not None and issubclass(self.result_class, PangeaResponseResult) and self.success
            else None
        )
        if not self.success:
            if self.http_status == 202:
                self.accepted_result = AcceptedResult(**self.raw_result) if self.raw_result is not None else None
            else:
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
    def http_status(self) -> int:  # type: ignore[return]
        if self.raw_response:
            if type(self.raw_response) == aiohttp.ClientResponse:
                return self.raw_response.status
            else:
                return self.raw_response.status_code  # type: ignore[union-attr]

    @property
    def url(self) -> str:
        return str(self.raw_response.url)  # type: ignore[union-attr]

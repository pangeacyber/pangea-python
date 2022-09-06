# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import dataclasses
import typing as t


class PangeaException(Exception):
    """Base Exception class for this library"""

    def __init__(self, message: str):
        super(Exception, self).__init__(message)
        self.message = message


class PangeaAPIException(PangeaException):
    """Exceptions raised during API calls"""


class ValidationException(PangeaAPIException):
    """Pangea Validation Errors denoting issues with an API request"""

    def __init__(self, message: str, field_errors: t.List["FieldError"]):
        super(ValidationException, self).__init__(message)
        self.field_errors = field_errors


class RateLimitException(PangeaAPIException):
    """Too many requests were made"""


class NoCreditException(PangeaAPIException):
    """API usage requires payment"""


class UnauthorizedException(PangeaAPIException):
    """User is not authorized to access a given resource"""

    def __init__(self, service_name: str, path: str):
        message = f"User is not authorized to access path {path} for service {service_name}"
        super(UnauthorizedException, self).__init__(message)


class ServiceNotEnabledException(PangeaAPIException):
    def __init__(self, service_name: str):
        message = f"{service_name} is not enabled. Go to console.pangea.cloud/service/{service_name} to enable"
        super(ServiceNotEnabledException, self).__init__(message)


class MissingConfigID(PangeaAPIException):
    """No config ID was provided in either token scopes or explicitly"""

    def __init__(self, service_name: str):
        super(MissingConfigID, self).__init__(
            f"Token did not contain a config scope for service {service_name}. Create a new token or provide a config ID explicitly in the service base"
        )


class ProviderErrorException(PangeaAPIException):
    """Downstream provider error"""


class InternalServiceErrorException(PangeaAPIException):
    """A pangea service error"""


class ServiceNotAvailableException(PangeaAPIException):
    """Service is not currently available"""


# Audit Specific Exceptions
#
class AuditException(PangeaException):
    """Audit service specific exceptions"""


class TreeNotFoundException(AuditException):
    """Tree was not found during a root inspection"""


# Embargo specific exceptions
class EmbargoException(PangeaException):
    """Audit service specific exceptions"""


class IPNotFoundException(EmbargoException):
    """IP address was not found"""


@dataclasses.dataclass
class FieldError:
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
    path: t.Optional[str] = None

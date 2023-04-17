# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from typing import List

from pangea.response import ErrorField, PangeaResponse


class PangeaException(Exception):
    """Base Exception class for this library"""

    def __init__(self, message: str):
        super(Exception, self).__init__(message)
        self.message = message


class PangeaAPIException(PangeaException):
    """Exceptions raised during API calls"""

    response: PangeaResponse

    def __init__(self, message: str, response: PangeaResponse):
        super(PangeaAPIException, self).__init__(message)
        self.response = response

    @property
    def errors(self) -> List[ErrorField]:
        return self.response.errors

    def __repr__(self) -> str:
        ret = f"Summary: {self.response.summary}\n"
        if self.response.errors:
            ret += "Errors: \n"
            for ef in self.response.errors:
                ret += f"\t {ef.detail}\n"
        return ret

    def __str__(self) -> str:
        ret = f"Summary: {self.response.summary}\n"
        if self.response.errors:
            ret += "Errors: \n"
            for ef in self.response.errors:
                ret += f"\t {ef.detail}\n"
        return ret


class ValidationException(PangeaAPIException):
    """Pangea Validation Errors denoting issues with an API request"""


class RateLimitException(PangeaAPIException):
    """Too many requests were made"""


class NoCreditException(PangeaAPIException):
    """API usage requires payment"""


class UnauthorizedException(PangeaAPIException):
    """User is not authorized to access a given resource"""

    def __init__(self, service_name: str, response: PangeaResponse):
        message = f"User is not authorized to access service {service_name}"
        super(UnauthorizedException, self).__init__(message, response)


class NotFound(PangeaAPIException):
    """Resource not found"""

    def __init__(self, url: str, response: PangeaResponse):
        message = f"Resource {url} not found"
        super(NotFound, self).__init__(message, response)


class ServiceNotEnabledException(PangeaAPIException):
    def __init__(self, service_name: str, response: PangeaResponse):
        message = f"{service_name} is not enabled. Go to console.pangea.cloud/service/{service_name} to enable"
        super(ServiceNotEnabledException, self).__init__(message, response)


class MissingConfigID(PangeaAPIException):
    """No config ID was provided in either token scopes or explicitly"""

    def __init__(self, service_name: str, response: PangeaResponse):
        super(MissingConfigID, self).__init__(
            f"Token did not contain a config scope for service {service_name}. Create a new token or provide a config ID explicitly in the service base",
            response,
        )


class NotFound(PangeaAPIException):
    """Resource not found"""

    def __init__(self, url: str, response: PangeaResponse):
        super(NotFound, self).__init__(f"Resource not found: {url}", response)


class ProviderErrorException(PangeaAPIException):
    """Downstream provider error"""


class InternalServerError(PangeaAPIException):
    """A pangea server error"""

    def __init__(self, response: PangeaResponse):
        message = f"summary: {response.summary}. request_id: {response.request_id}. request_time: {response.request_time}. response_time: ${response.response_time}"
        super().__init__(message, response)


class ServiceNotAvailableException(PangeaAPIException):
    """Service is not currently available"""


# Embargo specific exceptions
class EmbargoAPIException(PangeaAPIException):
    """Embargo service specific exceptions"""


class IPNotFoundException(EmbargoAPIException):
    """IP address was not found"""


class AuditAPIException(PangeaAPIException):
    """Audit API service specific exceptions"""


class TreeNotFoundException(AuditAPIException):
    """Tree was not found during a root inspection"""


class BadOffsetException(AuditAPIException):
    """Bad offset in results search"""


# Vault SDK specific exceptions
class VaultException(PangeaException):
    """Vault SDK specific exceptions"""


# Vault API specific exceptions
class VaultAPIException(PangeaAPIException):
    """Vault service specific exceptions"""


class ForbiddenVaultOperation(VaultAPIException):
    """Forbiden Vault operation"""


class VaultItemNotFound(VaultAPIException):
    """Vault item not found"""

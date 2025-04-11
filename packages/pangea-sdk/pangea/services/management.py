from __future__ import annotations

from collections.abc import Sequence
from typing import List, Literal, Optional, Union, overload

from pydantic import Field

from pangea.config import PangeaConfig
from pangea.response import APIRequestModel, PangeaResponse, PangeaResponseResult
from pangea.services.base import ServiceBase

__all__ = (
    "AccessClientCreateInfo",
    "AccessClientCreateInfo",
    "AccessClientInfo",
    "AccessClientInfo",
    "AccessClientListResult",
    "AccessClientSecretInfo",
    "AccessClientSecretInfoListResult",
    "AccessRole",
    "AccessRolesListResult",
    "ListProjectsFilter",
    "ListProjectsResult",
    "Management",
    "Organization",
    "Project",
)


class Organization(PangeaResponseResult):
    id: str
    name: str
    owner: str
    owner_email: Optional[str] = None
    created_at: str
    updated_at: str
    csp: str


class Project(PangeaResponseResult):
    id: str
    name: str
    org: str
    created_at: str
    updated_at: str
    geo: Literal["us", "eu"]
    """The geographical region for the project."""

    region: Literal["us-west-1", "us-east-1", "eu-central-1"]
    """The region for the project."""


class ListProjectsFilter(APIRequestModel):
    search: Optional[str] = None
    geo: Optional[str] = None
    region: Optional[str] = None


class ListProjectsResult(PangeaResponseResult):
    results: List[Project]
    """A list of projects"""

    count: int
    offset: Optional[int] = None


AccessClientTokenAuth = Literal["client_secret_basic", "client_secret_post"]
"""The authentication method for the token endpoint."""


class AccessClientInfo(PangeaResponseResult):
    """API Client information"""

    client_id: str
    """An ID for a service account"""
    created_at: str
    """A time in ISO-8601 format"""
    updated_at: str
    """A time in ISO-8601 format"""
    client_name: str
    scope: str
    """A list of space separated scope"""
    token_endpoint_auth_method: AccessClientTokenAuth
    """The authentication method for the token endpoint."""
    redirect_uris: List[str]
    """A list of allowed redirect URIs for the client."""
    grant_types: List[str]
    """A list of OAuth grant types that the client can use."""
    response_types: List[Optional[str]]
    """A list of OAuth response types that the client can use."""
    client_token_expires_in: Optional[int] = None
    """A positive time duration in seconds or null"""
    owner_id: str
    owner_username: str
    creator_id: str
    client_class: str


class AccessClientCreateInfo(AccessClientInfo):
    """API Client information with initial secret"""

    client_secret: str
    """An secret for an API Client"""
    client_secret_expires_at: str
    """A time in ISO-8601 format"""
    client_secret_name: str
    client_secret_description: str


AccessRegistryGroup = Literal["ai-guard-edge", "redact-edge", "private-cloud"]
"""A Pangea Registry Group"""


class AccessRole(PangeaResponseResult):
    """Service token information"""

    role: str
    type: str
    id: Union[str, AccessRegistryGroup]

    service: Optional[str] = None
    service_config_id: Optional[str] = None
    """An ID for a service config"""


class AccessClientListResult(PangeaResponseResult):
    clients: List[AccessClientInfo]
    count: int
    last: Optional[str] = None


class AccessClientSecretInfo(PangeaResponseResult):
    client_id: str
    """An ID for a service account"""
    client_secret_id: str
    """An ID for an API Client secret"""
    client_secret: str
    """An secret for an API Client"""
    client_secret_expires_at: str
    """A time in ISO-8601 format"""

    client_secret_name: Optional[str] = None
    client_secret_description: Optional[str] = None


class AccessClientSecretMetadata(PangeaResponseResult):
    source_ip: str
    user_agent: str
    creator: str
    creator_id: str
    creator_type: str


class AccessClientSecretInfoWithMetadata(PangeaResponseResult):
    client_id: str
    client_secret_id: str
    client_secret_expires_at: str
    client_secret_name: str
    client_secret_description: str
    created_at: str
    updated_at: str
    client_secret_metadata: AccessClientSecretMetadata


class AccessClientSecretInfoListResult(PangeaResponseResult):
    client_secrets: List[AccessClientSecretInfoWithMetadata] = Field(alias="client-secrets")
    count: int
    last: Optional[str] = None


class AccessRolesListResult(PangeaResponseResult):
    roles: List[AccessRole]
    count: int
    last: Optional[str] = None


class _Authorization(ServiceBase):
    service_name = "authorization.access"


class _Console(ServiceBase):
    service_name = "api.console"


class Management:
    """Management service client."""

    _authorization: _Authorization
    _console: _Console

    def __init__(
        self, token: str, config: PangeaConfig | None = None, logger_name: str = "pangea", config_id: str | None = None
    ) -> None:
        """
        Management client

        Initializes a new Management client.

        Args:
            token: Pangea API token.
            config: Configuration.
            logger_name: Logger name.
            config_id: Configuration ID.

        Examples:
             config = PangeaConfig(domain="pangea_domain")
             management = Management(token="pangea_token", config=config)
        """

        self._authorization = _Authorization(token, config, logger_name, config_id=config_id)
        self._console = _Console(token, config, logger_name, config_id=config_id)

    def get_org(self, org_id: str) -> PangeaResponse[Organization]:
        """
        Retrieve an organization

        OperationId: api.console_post_v1beta_platform_org_get

        Args:
            org_id: An Organization Pangea ID
        """

        return self._console.request.post("v1beta/platform/org/get", Organization, data={"id": org_id})

    def update_org(self, org_id: str, *, name: str) -> PangeaResponse[Organization]:
        """
        Update an organization

        OperationId: api.console_post_v1beta_platform_org_update

        Args:
            org_id: An Organization Pangea ID
        """

        return self._console.request.post("v1beta/platform/org/update", Organization, data={"id": org_id, "name": name})

    def get_project(self, project_id: str) -> PangeaResponse[Project]:
        """
        Retrieve a project

        OperationId: api.console_post_v1beta_platform_project_get

        Args:
            project_id: A Project Pangea ID
        """

        return self._console.request.post("v1beta/platform/project/get", Project, data={"id": project_id})

    def list_projects(
        self,
        org_id: str,
        *,
        filter: ListProjectsFilter | None = None,
        offset: int | None = None,
        limit: int | None = None,
    ) -> PangeaResponse[ListProjectsResult]:
        """
        List projects

        OperationId: api.console_post_v1beta_platform_project_list

        Args:
            org_id: An Organization Pangea ID
        """

        return self._console.request.post(
            "v1beta/platform/project/list",
            ListProjectsResult,
            data={"org_id": org_id, "filter": filter, "offset": offset, "limit": limit},
        )

    def create_project(
        self,
        org_id: str,
        name: str,
        geo: Literal["us", "eu"],
        *,
        region: Literal["us-west-1", "us-east-1", "eu-central-1"] | None = None,
    ) -> PangeaResponse[Project]:
        """
        Create a project

        OperationId: api.console_post_v1beta_platform_project_create

        Args:
            org_id: An Organization Pangea ID
            geo: The geographical region for the project
            region: The region for the project
        """

        return self._console.request.post(
            "v1beta/platform/project/create",
            Project,
            data={"org_id": org_id, "name": name, "geo": geo, "region": region},
        )

    def update_project(self, project_id: str, name: str) -> PangeaResponse[Project]:
        """
        Update a project

        OperationId: api.console_post_v1beta_platform_project_update

        Args:
            project_id: A Project Pangea ID
        """

        return self._console.request.post(
            "v1beta/platform/project/update", Project, data={"id": project_id, "name": name}
        )

    def delete_project(self, project_id: str) -> PangeaResponse[PangeaResponseResult]:
        """
        Delete a project

        OperationId: api.console_post_v1beta_platform_project_delete

        Args:
            project_id: A Project Pangea ID
        """

        return self._console.request.post(
            "v1beta/platform/project/delete", PangeaResponseResult, data={"id": project_id}
        )

    def create_client(
        self,
        client_name: str,
        scope: str,
        *,
        token_endpoint_auth_method: AccessClientTokenAuth | None = None,
        redirect_uris: Sequence[str] | None = None,
        grant_types: Sequence[str] | None = None,
        response_types: Sequence[str | None] | None = None,
        client_secret_expires_in: int | None = None,
        client_token_expires_in: int | None = None,
        client_secret_name: str | None = None,
        client_secret_description: str | None = None,
        roles: Sequence[AccessRole] | None = None,
    ) -> AccessClientCreateInfo:
        """
        Create Platform Client

        OperationId: createPlatformClient

        Args:
            scope: A list of space separated scope
            token_endpoint_auth_method: The authentication method for the token endpoint.
            redirect_uris: A list of allowed redirect URIs for the client.
            grant_types: A list of OAuth grant types that the client can use.
            response_types: A list of OAuth response types that the client can use.
            client_secret_expires_in: A positive time duration in seconds or null
            client_token_expires_in: A positive time duration in seconds or null
            roles: A list of roles
        """

        return self._authorization.request.post(
            "v1beta/oauth/clients/register",
            data={
                "client_name": client_name,
                "scope": scope,
                "token_endpoint_auth_method": token_endpoint_auth_method,
                "redirect_uris": redirect_uris,
                "grant_types": grant_types,
                "response_types": response_types,
                "client_secret_expires_in": client_secret_expires_in,
                "client_token_expires_in": client_token_expires_in,
                "client_secret_name": client_secret_name,
                "client_secret_description": client_secret_description,
                "roles": roles,
            },
            result_class=AccessClientCreateInfo,
            pangea_response=False,
        )

    def list_clients(
        self,
        *,
        created_at: str | None = None,
        created_at__gt: str | None = None,
        created_at__gte: str | None = None,
        created_at__lt: str | None = None,
        created_at__lte: str | None = None,
        client_id: str | None = None,
        client_id__contains: Sequence[str] | None = None,
        client_id__in: Sequence[str] | None = None,
        client_name: str | None = None,
        client_name__contains: Sequence[str] | None = None,
        client_name__in: Sequence[str] | None = None,
        scopes: Sequence[str] | None = None,
        updated_at: str | None = None,
        updated_at__gt: str | None = None,
        updated_at__gte: str | None = None,
        updated_at__lt: str | None = None,
        updated_at__lte: str | None = None,
        last: str | None = None,
        order: Literal["asc", "desc"] | None = None,
        order_by: Literal["id", "created_at", "updated_at", "name", "token_type"] | None = None,
        size: int | None = None,
    ) -> AccessClientListResult:
        """
        List platform clients

        OperationId: listPlatformClients

        Args:
            created_at: Only records where created_at equals this value.
            created_at__gt: Only records where created_at is greater than this value.
            created_at__gte: Only records where created_at is greater than or equal to this value.
            created_at__lt: Only records where created_at is less than this value.
            created_at__lte: Only records where created_at is less than or equal to this value.
            client_id: Only records where id equals this value.
            client_id__contains: Only records where id includes each substring.
            client_id__in: Only records where id equals one of the provided substrings.
            client_name: Only records where name equals this value.
            client_name__contains: Only records where name includes each substring.
            client_name__in: Only records where name equals one of the provided substrings.
            scopes: A list of tags that all must be present.
            updated_at: Only records where updated_at equals this value.
            updated_at__gt: Only records where updated_at is greater than this value.
            updated_at__gte: Only records where updated_at is greater than or equal to this value.
            updated_at__lt: Only records where updated_at is less than this value.
            updated_at__lte: Only records where updated_at is less than or equal to this value.
            last: Reflected value from a previous response to obtain the next page of results.
            order: Order results asc(ending) or desc(ending).
            order_by: Which field to order results by.
            size: Maximum results to include in the response.
        """

        return self._authorization.request.get(
            "v1beta/oauth/clients",
            params={
                "created_at": created_at,
                "created_at__gt": created_at__gt,
                "created_at__gte": created_at__gte,
                "created_at__lt": created_at__lt,
                "created_at__lte": created_at__lte,
                "client_id": client_id,
                "client_id__contains": client_id__contains,
                "client_id__in": client_id__in,
                "client_name": client_name,
                "client_name__contains": client_name__contains,
                "client_name__in": client_name__in,
                "scopes": scopes,
                "updated_at": updated_at,
                "updated_at__gt": updated_at__gt,
                "updated_at__gte": updated_at__gte,
                "updated_at__lt": updated_at__lt,
                "updated_at__lte": updated_at__lte,
                "last": last,
                "order": order,
                "order_by": order_by,
                "size": size,
            },
            result_class=AccessClientListResult,
            pangea_response=False,
        )

    def get_client(self, client_id: str) -> AccessClientInfo:
        """
        Get a platform client

        OperationId: getPlatformClient
        """

        return self._authorization.request.get(
            f"v1beta/oauth/clients/{client_id}", result_class=AccessClientInfo, pangea_response=False
        )

    @overload
    def update_client(
        self,
        client_id: str,
        *,
        scope: str,
        token_endpoint_auth_method: AccessClientTokenAuth | None = None,
        redirect_uris: Sequence[str] | None = None,
        response_types: Sequence[str | None] | None = None,
        grant_types: Sequence[str] | None = None,
    ) -> AccessClientInfo:
        """
        Update platform client's scope
        """

    @overload
    def update_client(
        self,
        client_id: str,
        *,
        client_name: str,
        token_endpoint_auth_method: AccessClientTokenAuth | None = None,
        redirect_uris: Sequence[str] | None = None,
        response_types: Sequence[str | None] | None = None,
        grant_types: Sequence[str] | None = None,
    ) -> AccessClientInfo:
        """
        Update platform client's name
        """

    def update_client(
        self,
        client_id: str,
        *,
        scope: str | None = None,
        client_name: str | None = None,
        token_endpoint_auth_method: AccessClientTokenAuth | None = None,
        redirect_uris: Sequence[str] | None = None,
        response_types: Sequence[str | None] | None = None,
        grant_types: Sequence[str] | None = None,
    ) -> AccessClientInfo:
        """
        Update platform client
        """

        return self._authorization.request.post(
            f"v1beta/oauth/clients/{client_id}",
            data={
                "client_id": client_id,
                "scope": scope,
                "client_name": client_name,
                "token_endpoint_auth_method": token_endpoint_auth_method,
                "redirect_uris": redirect_uris,
                "response_types": response_types,
                "grant_types": grant_types,
            },
            result_class=AccessClientInfo,
            pangea_response=False,
        )

    def delete_client(self, client_id: str) -> None:
        """
        Delete platform client

        OperationId: deletePlatformClient
        """

        return self._authorization.request.delete(f"v1beta/oauth/clients/{client_id}")

    def create_client_secret(
        self,
        client_id: str,
        client_secret_id: str,
        *,
        client_secret_expires_in: int | None = None,
        client_secret_name: str | None = None,
        client_secret_description: str | None = None,
    ) -> AccessClientSecretInfo:
        """
        Create client secret

        OperationId: createClientSecret

        Args:
            client_secret_expires_in: A positive time duration in seconds
        """

        return self._authorization.request.post(
            f"v1beta/oauth/clients/{client_id}/secrets",
            data={
                "client_id": client_id,
                "client_secret_id": client_secret_id,
                "client_secret_expires_in": client_secret_expires_in,
                "client_secret_name": client_secret_name,
                "client_secret_description": client_secret_description,
            },
            result_class=AccessClientSecretInfo,
            pangea_response=False,
        )

    def list_client_secret_metadata(
        self,
        client_id: str,
        *,
        created_at: str | None = None,
        created_at__gt: str | None = None,
        created_at__gte: str | None = None,
        created_at__lt: str | None = None,
        created_at__lte: str | None = None,
        client_secret_name: str | None = None,
        client_secret_name__contains: Sequence[str] | None = None,
        client_secret_name__in: Sequence[str] | None = None,
        last: str | None = None,
        order: Literal["asc", "desc"] | None = None,
        order_by: Literal["id", "created_at", "updated_at", "client_secret_id"] | None = None,
        size: int | None = None,
    ) -> AccessClientSecretInfoListResult:
        """
        List client secret metadata

        OperationId: listClientSecretMetadata

        Args:
            client_id: The client ID to list secrets for
            created_at: Only records where created_at equals this value.
            created_at__gt: Only records where created_at is greater than this value.
            created_at__gte: Only records where created_at is greater than or equal to this value.
            created_at__lt: Only records where created_at is less than this value.
            created_at__lte: Only records where created_at is less than or equal to this value.
            client_secret_name: Only records where name equals this value.
            client_secret_name__contains: Only records where name includes each substring.
            client_secret_name__in: Only records where name equals one of the provided substrings.
            last: Reflected value from a previous response to obtain the next page of results.
            order: Order results asc(ending) or desc(ending).
            order_by: Which field to order results by.
            size: Maximum results to include in the response.
        """

        return self._authorization.request.get(
            f"v1beta/oauth/clients/{client_id}/secrets/metadata",
            params={
                "created_at": created_at,
                "created_at__gt": created_at__gt,
                "created_at__gte": created_at__gte,
                "created_at__lt": created_at__lt,
                "created_at__lte": created_at__lte,
                "client_secret_name": client_secret_name,
                "client_secret_name__contains": client_secret_name__contains,
                "client_secret_name__in": client_secret_name__in,
                "last": last,
                "order": order,
                "order_by": order_by,
                "size": size,
            },
            result_class=AccessClientSecretInfoListResult,
            pangea_response=False,
        )

    def revoke_client_secret(self, client_id: str, client_secret_id: str) -> None:
        """
        Revoke client secret

        OperationId: revokeClientSecret
        """

        return self._authorization.request.delete(f"v1beta/oauth/clients/{client_id}/secrets/{client_secret_id}")

    def update_client_secret(
        self,
        client_id: str,
        client_secret_id: str,
        *,
        client_secret_expires_in: int | None = None,
        client_secret_name: str | None = None,
        client_secret_description: str | None = None,
    ) -> AccessClientSecretInfo:
        """
        Update client secret

        OperationId: updateClientSecret

        Args:
            client_secret_expires_in: A positive time duration in seconds
        """

        return self._authorization.request.post(
            f"v1beta/oauth/clients/{client_id}/secrets/{client_secret_id}",
            data={
                "client_secret_expires_in": client_secret_expires_in,
                "client_secret_name": client_secret_name,
                "client_secret_description": client_secret_description,
            },
            result_class=AccessClientSecretInfo,
            pangea_response=False,
        )

    def list_client_roles(
        self,
        client_id: str,
        *,
        resource_type: str | None = None,
        resource_id: str | None = None,
        role: str | None = None,
    ) -> AccessRolesListResult:
        """
        List client roles

        OperationId: listClientRoles
        """

        return self._authorization.request.get(
            f"v1beta/oauth/clients/{client_id}/roles",
            params={"resource_type": resource_type, "resource_id": resource_id, "role": role},
            result_class=AccessRolesListResult,
            pangea_response=False,
        )

    def grant_client_access(self, client_id: str, roles: Sequence[AccessRole], scope: str) -> PangeaResponseResult:
        """
        Grant client access

        OperationId: grantClientRoles

        Args:
            roles: A list of roles
            scope: A list of space separated scope
        """

        return self._authorization.request.post(
            f"v1beta/oauth/clients/{client_id}/grant",
            data={"roles": roles, "scope": scope},
            result_class=PangeaResponseResult,
            pangea_response=False,
        )

    def revoke_client_access(self, client_id: str, roles: Sequence[AccessRole], scope: str) -> PangeaResponseResult:
        """
        Revoke client access

        OperationId: revokeClientRoles

        Args:
            roles: A list of roles
            scope: A list of space separated scope
        """

        return self._authorization.request.post(
            f"v1beta/oauth/clients/{client_id}/revoke",
            data={"roles": roles, "scope": scope},
            result_class=PangeaResponseResult,
            pangea_response=False,
        )

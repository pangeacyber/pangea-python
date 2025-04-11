from __future__ import annotations

from typing import List, Literal, Optional

from pangea.config import PangeaConfig
from pangea.response import APIRequestModel, PangeaResponse, PangeaResponseResult
from pangea.services.base import ServiceBase

__all__ = ("ListProjectsFilter", "ListProjectsResult", "Management", "Organization", "Project")


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


class Management(ServiceBase):
    """Management service client."""

    service_name = "api.console"

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
             redact = Management(token="pangea_token", config=config)
        """

        super().__init__(token, config, logger_name, config_id=config_id)

    def get_org(self, org_id: str) -> PangeaResponse[Organization]:
        """
        Retrieve an organization

        OperationId: api.console_post_v1beta_platform_org_get

        Args:
            org_id: An Organization Pangea ID
        """

        return self.request.post("v1beta/platform/org/get", Organization, data={"id": org_id})

    def update_org(self, org_id: str, *, name: str) -> PangeaResponse[Organization]:
        """
        Update an organization

        OperationId: api.console_post_v1beta_platform_org_update

        Args:
            org_id: An Organization Pangea ID
        """

        return self.request.post("v1beta/platform/org/update", Organization, data={"id": org_id, "name": name})

    def get_project(self, project_id: str) -> PangeaResponse[Project]:
        """
        Retrieve a project

        OperationId: api.console_post_v1beta_platform_project_get

        Args:
            project_id: A Project Pangea ID
        """

        return self.request.post("v1beta/platform/project/get", Project, data={"id": project_id})

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

        return self.request.post(
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

        return self.request.post(
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

        return self.request.post("v1beta/platform/project/update", Project, data={"id": project_id, "name": name})

    def delete_project(self, project_id: str) -> PangeaResponse[PangeaResponseResult]:
        """
        Delete a project

        OperationId: api.console_post_v1beta_platform_project_delete

        Args:
            project_id: A Project Pangea ID
        """

        return self.request.post("v1beta/platform/project/delete", PangeaResponseResult, data={"id": project_id})

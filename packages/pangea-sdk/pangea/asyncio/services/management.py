from __future__ import annotations

from typing import Literal

from pangea.asyncio.services.base import ServiceBaseAsync
from pangea.config import PangeaConfig
from pangea.response import PangeaResponse, PangeaResponseResult
from pangea.services.management import ListProjectsFilter, ListProjectsResult, Organization, Project

__all__ = ("ManagementAsync",)


class ManagementAsync(ServiceBaseAsync):
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

    async def get_org(self, org_id: str) -> PangeaResponse[Organization]:
        """
        Retrieve an organization

        OperationId: api.console_post_v1beta_platform_org_get

        Args:
            org_id: An Organization Pangea ID
        """

        return await self.request.post("v1beta/platform/org/get", Organization, data={"id": org_id})

    async def update_org(self, org_id: str, *, name: str) -> PangeaResponse[Organization]:
        """
        Update an organization

        OperationId: api.console_post_v1beta_platform_org_update

        Args:
            org_id: An Organization Pangea ID
        """

        return await self.request.post("v1beta/platform/org/update", Organization, data={"id": org_id, "name": name})

    async def get_project(self, project_id: str) -> PangeaResponse[Project]:
        """
        Retrieve a project

        OperationId: api.console_post_v1beta_platform_project_get

        Args:
            project_id: A Project Pangea ID
        """

        return await self.request.post("v1beta/platform/project/get", Project, data={"id": project_id})

    async def list_projects(
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

        return await self.request.post(
            "v1beta/platform/project/list",
            ListProjectsResult,
            data={"org_id": org_id, "filter": filter, "offset": offset, "limit": limit},
        )

    async def create_project(
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

        return await self.request.post(
            "v1beta/platform/project/create",
            Project,
            data={"org_id": org_id, "name": name, "geo": geo, "region": region},
        )

    async def update_project(self, project_id: str, name: str) -> PangeaResponse[Project]:
        """
        Update a project

        OperationId: api.console_post_v1beta_platform_project_update

        Args:
            project_id: A Project Pangea ID
        """

        return await self.request.post("v1beta/platform/project/update", Project, data={"id": project_id, "name": name})

    async def delete_project(self, project_id: str) -> PangeaResponse[PangeaResponseResult]:
        """
        Delete a project

        OperationId: api.console_post_v1beta_platform_project_delete

        Args:
            project_id: A Project Pangea ID
        """

        return await self.request.post("v1beta/platform/project/delete", PangeaResponseResult, data={"id": project_id})

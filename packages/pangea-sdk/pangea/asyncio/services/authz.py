# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pangea.asyncio.services.base import ServiceBaseAsync
from pangea.config import PangeaConfig
from pangea.response import PangeaResponse
from pangea.services.authz import (
    BulkCheckRequestItem,
    BulkCheckResult,
    CheckResult,
    ItemOrder,
    ListResourcesRequest,
    ListResourcesResult,
    ListSubjectsRequest,
    ListSubjectsResult,
    Resource,
    Subject,
    Tuple,
    TupleCreateResult,
    TupleDeleteRequest,
    TupleDeleteResult,
    TupleListFilter,
    TupleListRequest,
    TupleListResult,
    TupleOrderBy,
)


class AuthZAsync(ServiceBaseAsync):
    """AuthZ service client.

    Provides methods to interact with the Pangea AuthZ Service.
    Documentation for the AuthZ Service API can be found at
    <https://pangea.cloud/docs/api/authz>.

    Examples:
        import os
        from pangea.asyncio.services import AuthZAsync
        from pangea.config import PangeaConfig

        PANGEA_TOKEN = os.getenv("PANGEA_AUTHZ_TOKEN")

        authz_config = PangeaConfig(domain="aws.us.pangea.cloud")

        # Setup Pangea AuthZ service client
        authz = AuthZAsync(token=PANGEA_TOKEN, config=authz_config)
    """

    service_name = "authz"

    def __init__(
        self, token: str, config: PangeaConfig | None = None, logger_name: str = "pangea", config_id: str | None = None
    ) -> None:
        """
        AuthZ client

        Initializes a new AuthZ client.

        Args:
            token: Pangea API token.
            config: Configuration.
            logger_name: Logger name.
            config_id: Configuration ID.

        Examples:
             config = PangeaConfig(domain="aws.us.pangea.cloud")
             authz = AuthZAsync(token="pangea_token", config=config)
        """

        super().__init__(token, config, logger_name, config_id=config_id)

    async def tuple_create(self, tuples: Sequence[Tuple]) -> PangeaResponse[TupleCreateResult]:
        """Create tuples.

        Create tuples in the AuthZ Service. The request will fail if there is no schema
        or the tuples do not validate against the schema.

        Args:
            tuples: Tuples to be created.

        Raises:
            PangeaAPIException: If an API Error happens.

        Returns:
            Pangea Response with empty result.
            Available response fields can be found in our
            [API Documentation](https://pangea.cloud/docs/api/authz#/v1/tuple/create-post).

        Examples:
            await authz.tuple_create(
                tuples=[
                    Tuple(
                        resource=Resource(type="file", id="file_1"),
                        relation="owner",
                        subject=Subject(type="user", id="user_1"),
                    )
                ]
            )
        """

        return await self.request.post("v1/tuple/create", TupleCreateResult, data={"tuples": tuples})

    async def tuple_list(
        self,
        filter: TupleListFilter,
        size: int | None = None,
        last: str | None = None,
        order: ItemOrder | None = None,
        order_by: TupleOrderBy | None = None,
    ) -> PangeaResponse[TupleListResult]:
        """List tuples.

        Return a paginated list of filtered tuples. The filter is given in terms
        of a tuple. Fill out the fields that you want to filter. If the filter
        is empty it will return all the tuples.

        Args:
            filter: The filter for listing tuples.
            size: The size of the result set. Default is None.
            last: The last token from a previous response. Default is None.
            order: Order results asc(ending) or desc(ending).
            order_by: Which field to order results by.

        Raises:
            PangeaAPIException: If an API Error happens.

        Returns:
            Pangea Response with a list of tuples and the last token.
            Available response fields can be found in our
            [API Documentation](https://pangea.cloud/docs/api/authz#/v1/tuple/list-post).

        Examples:
            await authz.tuple_list(TupleListFilter(subject_type="user", subject_id="user_1"))
        """
        input_data = TupleListRequest(
            filter=filter.model_dump(exclude_none=True), size=size, last=last, order=order, order_by=order_by
        )
        return await self.request.post("v1/tuple/list", TupleListResult, data=input_data.model_dump(exclude_none=True))

    async def tuple_delete(self, tuples: list[Tuple]) -> PangeaResponse[TupleDeleteResult]:
        """Delete tuples.

        Delete tuples in the AuthZ Service.

        Args:
            tuples: Tuples to be deleted.

        Raises:
            PangeaAPIException: If an API Error happens.

        Returns:
            Pangea Response with empty result.
            Available response fields can be found in our
            [API Documentation](https://pangea.cloud/docs/api/authz#/v1/tuple/delete-post).

        Examples:
            await authz.tuple_delete(
                tuples=[
                    Tuple(
                        resource=Resource(type="file", id="file_1"),
                        relation="owner",
                        subject=Subject(type="user", id="user_1"),
                    )
                ]
            )
        """

        input_data = TupleDeleteRequest(tuples=tuples)
        return await self.request.post(
            "v1/tuple/delete", TupleDeleteResult, data=input_data.model_dump(exclude_none=True)
        )

    async def check(
        self,
        resource: Resource,
        action: str,
        subject: Subject,
        debug: bool | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> PangeaResponse[CheckResult]:
        """Perform a check request.

        Check if a subject has permission to perform an action on the resource.

        Args:
            resource: The resource to check.
            action: The action to check.
            subject: The subject to check.
            debug: Setting this value to True will provide a detailed analysis of the check.
            attributes: Additional attributes for the check.

        Raises:
            PangeaAPIException: If an API Error happens.

        Returns:
            Pangea Response with the result of the check.
            Available response fields can be found in our
            [API Documentation](https://pangea.cloud/docs/api/authz#/v1/check-post).

        Examples:
            await authz.check(
                resource=Resource(type="file", id="file_1"),
                action="update",
                subject=Subject(type="user", id="user_1"),
                debug=True,
            )
        """

        return await self.request.post(
            "v1/check",
            CheckResult,
            data={"resource": resource, "action": action, "subject": subject, "debug": debug, "attributes": attributes},
        )

    async def bulk_check(
        self,
        checks: Sequence[BulkCheckRequestItem],
        *,
        debug: bool | None = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> PangeaResponse[BulkCheckResult]:
        """Perform a bulk check request

        Perform multiple checks in a single request to see if a subjects have
        permission to do actions on the resources.

        Args:
            checks: Check requests to perform.
            debug: In the event of an allowed check, return a path that granted access.
            attributes: A JSON object of attribute data.

        Examples:
            await authz.bulk_check(
                checks=[
                    BulkCheckRequestItem(
                        resource=Resource(type="file", id="file_1"),
                        action="read",
                        subject=Subject(type="user", id="user_1", action="read"),
                    )
                ]
            )
        """

        return await self.request.post(
            "v1/check/bulk", BulkCheckResult, data={"checks": checks, "debug": debug, "attributes": attributes}
        )

    async def list_resources(
        self, type: str, action: str, subject: Subject, attributes: dict[str, Any] | None = None
    ) -> PangeaResponse[ListResourcesResult]:
        """List resources.

        Given a type, action, and subject, list all the resources in the
        type that the subject has access to the action with.

        Args:
            type: The type to filter resources.
            action: The action to filter resources.
            subject: The subject to filter resources.
            attributes: A JSON object of attribute data.

        Raises:
            PangeaAPIException: If an API Error happens.

        Returns:
            Pangea Response with a list of resource IDs.
            Available response fields can be found in our
            [API Documentation](https://pangea.cloud/docs/api/authz#/v1/list-resources-post).

        Examples:
            await authz.list_resources(
                type="file",
                action="update",
                subject=Subject(type="user", id="user_1"),
            )
        """

        input_data = ListResourcesRequest(type=type, action=action, subject=subject, attributes=attributes)
        return await self.request.post(
            "v1/list-resources", ListResourcesResult, data=input_data.model_dump(exclude_none=True)
        )

    async def list_subjects(
        self, resource: Resource, action: str, attributes: dict[str, Any] | None = None
    ) -> PangeaResponse[ListSubjectsResult]:
        """List subjects.

        Given a resource and an action, return the list of subjects who have
        access to the action for the given resource.

        Args:
            resource: The resource to filter subjects.
            action: The action to filter subjects.
            attributes: A JSON object of attribute data.

        Raises:
            PangeaAPIException: If an API Error happens.

        Returns:
            Pangea Response with a list of subjects.
            Available response fields can be found in our
            [API Documentation](https://pangea.cloud/docs/api/authz#/v1/list-subjects-post).

        Examples:
            await authz.list_subjects(
                resource=Resource(type="file", id="file_1"),
                action="update",
            )
        """

        input_data = ListSubjectsRequest(resource=resource, action=action, attributes=attributes)
        return await self.request.post(
            "v1/list-subjects", ListSubjectsResult, data=input_data.model_dump(exclude_none=True)
        )

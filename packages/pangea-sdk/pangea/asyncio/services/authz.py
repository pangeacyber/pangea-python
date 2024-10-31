# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pangea.asyncio.services.base import ServiceBaseAsync
from pangea.config import PangeaConfig
from pangea.response import PangeaResponse
from pangea.services.authz import (
    CheckRequest,
    CheckResult,
    ItemOrder,
    ListResourcesRequest,
    ListResourcesResult,
    ListSubjectsRequest,
    ListSubjectsResult,
    Resource,
    Subject,
    Tuple,
    TupleCreateRequest,
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

    async def tuple_create(self, tuples: List[Tuple]) -> PangeaResponse[TupleCreateResult]:
        """Create tuples.

        Create tuples in the AuthZ Service. The request will fail if there is no schema
        or the tuples do not validate against the schema.

        Args:
            tuples (List[Tuple]): List of tuples to be created.

        Raises:
            PangeaAPIException: If an API Error happens.

        Returns:
            Pangea Response with empty result.
            Available response fields can be found in our
            [API Documentation](https://pangea.cloud/docs/api/authz#/v1/tuple/create).

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

        input_data = TupleCreateRequest(tuples=tuples)
        return await self.request.post(
            "v1/tuple/create", TupleCreateResult, data=input_data.model_dump(exclude_none=True)
        )

    async def tuple_list(
        self,
        filter: TupleListFilter,
        size: Optional[int] = None,
        last: Optional[str] = None,
        order: Optional[ItemOrder] = None,
        order_by: Optional[TupleOrderBy] = None,
    ) -> PangeaResponse[TupleListResult]:
        """List tuples.

        Return a paginated list of filtered tuples. The filter is given in terms
        of a tuple. Fill out the fields that you want to filter. If the filter
        is empty it will return all the tuples.

        Args:
            filter (TupleListFilter): The filter for listing tuples.
            size (Optional[int]): The size of the result set. Default is None.
            last (Optional[str]): The last token from a previous response. Default is None.
            order (Optional[ItemOrder]): Order results asc(ending) or desc(ending).
            order_by (Optional[TupleOrderBy]): Which field to order results by.

        Raises:
            PangeaAPIException: If an API Error happens.

        Returns:
            Pangea Response with a list of tuples and the last token.
            Available response fields can be found in our
            [API Documentation](https://pangea.cloud/docs/api/authz#/v1/tuple/list).

        Examples:
            await authz.tuple_list(TupleListFilter(subject_type="user", subject_id="user_1"))
        """
        input_data = TupleListRequest(
            filter=filter.model_dump(exclude_none=True), size=size, last=last, order=order, order_by=order_by
        )
        return await self.request.post("v1/tuple/list", TupleListResult, data=input_data.model_dump(exclude_none=True))

    async def tuple_delete(self, tuples: List[Tuple]) -> PangeaResponse[TupleDeleteResult]:
        """Delete tuples.

        Delete tuples in the AuthZ Service.

        Args:
            tuples (List[Tuple]): List of tuples to be deleted.

        Raises:
            PangeaAPIException: If an API Error happens.

        Returns:
            Pangea Response with empty result.
            Available response fields can be found in our
            [API Documentation](https://pangea.cloud/docs/api/authz#/v1/tuple/delete).

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
        debug: Optional[bool] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> PangeaResponse[CheckResult]:
        """Perform a check request.

        Check if a subject has permission to perform an action on the resource.

        Args:
            resource (Resource): The resource to check.
            action (str): The action to check.
            subject (Subject): The subject to check.
            debug (Optional[bool]): Setting this value to True will provide a detailed analysis of the check.
            attributes (Optional[Dict[str, Any]]): Additional attributes for the check.

        Raises:
            PangeaAPIException: If an API Error happens.

        Returns:
            Pangea Response with the result of the check.
            Available response fields can be found in our
            [API Documentation](https://pangea.cloud/docs/api/authz#/v1/check).

        Examples:
            await authz.check(
                resource=Resource(type="file", id="file_1"),
                action="update",
                subject=Subject(type="user", id="user_1"),
                debug=True,
            )
        """

        input_data = CheckRequest(resource=resource, action=action, subject=subject, debug=debug, attributes=attributes)
        return await self.request.post("v1/check", CheckResult, data=input_data.model_dump(exclude_none=True))

    async def list_resources(
        self, type: str, action: str, subject: Subject, attributes: Optional[Dict[str, Any]] = None
    ) -> PangeaResponse[ListResourcesResult]:
        """List resources.

        Given a type, action, and subject, list all the resources in the
        type that the subject has access to the action with.

        Args:
            type (str): The type to filter resources.
            action (str): The action to filter resources.
            subject (Subject): The subject to filter resources.
            attributes (Optional[Dict[str, Any]]): A JSON object of attribute data.

        Raises:
            PangeaAPIException: If an API Error happens.

        Returns:
            Pangea Response with a list of resource IDs.
            Available response fields can be found in our
            [API Documentation](https://pangea.cloud/docs/api/authz#/v1/list-resources).

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
        self, resource: Resource, action: str, attributes: Optional[Dict[str, Any]] = None
    ) -> PangeaResponse[ListSubjectsResult]:
        """List subjects.

        Given a resource and an action, return the list of subjects who have
        access to the action for the given resource.

        Args:
            resource (Resource): The resource to filter subjects.
            action (str): The action to filter subjects.
            attributes (Optional[Dict[str, Any]]): A JSON object of attribute data.

        Raises:
            PangeaAPIException: If an API Error happens.

        Returns:
            Pangea Response with a list of subjects.
            Available response fields can be found in our
            [API Documentation](https://pangea.cloud/docs/api/authz#/v1/list-subjects).

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

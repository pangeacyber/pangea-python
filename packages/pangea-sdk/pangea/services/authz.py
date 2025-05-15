# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

# TODO: Use `list` instead of `List`.
# ruff: noqa: UP006, UP035

from __future__ import annotations

import enum
from typing import Any, Dict, List, Optional, Union

from pangea.config import PangeaConfig
from pangea.response import APIRequestModel, APIResponseModel, PangeaResponse, PangeaResponseResult
from pangea.services.base import ServiceBase


class ItemOrder(str, enum.Enum):
    ASC = "asc"
    DESC = "desc"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class TupleOrderBy(str, enum.Enum):
    RESOURCE_TYPE = "resource_type"
    RESOURCE_ID = "resource_id"
    RELATION = "relation"
    SUBJECT_TYPE = "subject_type"
    SUBJECT_ID = "subject_id"
    SUBJECT_ACTION = "subject_action"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class Resource(PangeaResponseResult):
    type: str
    id: Optional[str] = None


class Subject(PangeaResponseResult):
    type: str
    id: Optional[str] = None
    action: Optional[str] = None


class Tuple(PangeaResponseResult):
    resource: Resource
    relation: str
    subject: Subject
    expires_at: Optional[str] = None
    """A time in ISO-8601 format"""


class TupleCreateRequest(APIRequestModel):
    tuples: List[Tuple]


class TupleCreateResult(PangeaResponseResult):
    pass


class TupleListFilter(APIRequestModel):
    resource_type: Optional[str] = None
    """Only records where resource type equals this value."""
    resource_type__contains: Optional[List[str]] = None
    """Only records where resource type includes each substring."""
    resource_type__in: Optional[List[str]] = None
    """Only records where resource type equals one of the provided substrings."""
    resource_id: Optional[str] = None
    """Only records where resource id equals this value."""
    resource_id__contains: Optional[List[str]] = None
    """Only records where resource id includes each substring."""
    resource_id__in: Optional[List[str]] = None
    """Only records where resource id equals one of the provided substrings."""
    relation: Optional[str] = None
    """Only records where relation equals this value."""
    relation__contains: Optional[List[str]] = None
    """Only records where relation includes each substring."""
    relation__in: Optional[List[str]] = None
    """Only records where relation equals one of the provided substrings."""
    subject_type: Optional[str] = None
    """Only records where subject type equals this value."""
    subject_type__contains: Optional[List[str]] = None
    """Only records where subject type includes each substring."""
    subject_type__in: Optional[List[str]] = None
    """Only records where subject type equals one of the provided substrings."""
    subject_id: Optional[str] = None
    """Only records where subject id equals this value."""
    subject_id__contains: Optional[List[str]] = None
    """Only records where subject id includes each substring."""
    subject_id__in: Optional[List[str]] = None
    """Only records where subject id equals one of the provided substrings."""
    subject_action: Optional[str] = None
    """Only records where subject action equals this value."""
    subject_action__contains: Optional[List[str]] = None
    """Only records where subject action includes each substring."""
    subject_action__in: Optional[List[str]] = None
    """Only records where subject action equals one of the provided substrings."""
    expires_at: Optional[str] = None
    """Only records where expires_at equals this value."""
    expires_at__gt: Optional[str] = None
    """Only records where expires_at is greater than this value."""
    expires_at__gte: Optional[str] = None
    """Only records where expires_at is greater than or equal to this value."""
    expires_at__lt: Optional[str] = None
    """Only records where expires_at is less than this value."""
    expires_at__lte: Optional[str] = None
    """Only records where expires_at is less than or equal to this value."""


class TupleListRequest(APIRequestModel):
    filter: Optional[Union[Dict, TupleListFilter]] = None
    size: Optional[int] = None
    last: Optional[str] = None
    order: Optional[ItemOrder] = None
    order_by: Optional[TupleOrderBy] = None


class TupleListResult(PangeaResponseResult):
    tuples: List[Tuple]
    last: str
    count: int


class TupleDeleteRequest(APIRequestModel):
    tuples: List[Tuple]


class TupleDeleteResult(PangeaResponseResult):
    pass


class CheckRequest(APIRequestModel):
    resource: Resource
    action: str
    subject: Subject
    debug: Optional[bool] = None
    """In the event of an allowed check, return a path that granted access."""
    attributes: Optional[Dict[str, Any]] = None
    """A JSON object of attribute data."""


class DebugPath(APIResponseModel):
    type: str
    id: str
    action: Optional[str] = None


class Debug(APIResponseModel):
    path: List[DebugPath]


class CheckResult(PangeaResponseResult):
    schema_id: str
    schema_version: int
    depth: int
    allowed: bool
    debug: Optional[Debug] = None


class ListResourcesRequest(APIRequestModel):
    type: str
    action: str
    subject: Subject
    attributes: Optional[Dict[str, Any]] = None


class ListResourcesResult(PangeaResponseResult):
    ids: List[str]


class ListSubjectsRequest(APIRequestModel):
    resource: Resource
    action: str
    attributes: Optional[Dict[str, Any]] = None
    debug: Optional[bool] = None
    """Return a path for each found subject"""


class ListSubjectsResult(PangeaResponseResult):
    subjects: List[Subject]


class AuthZ(ServiceBase):
    """AuthZ service client.

    Provides methods to interact with the Pangea AuthZ Service.
    Documentation for the AuthZ Service API can be found at
    <https://pangea.cloud/docs/api/authz>.

    Examples:
        import os
        from pangea.config import PangeaConfig
        from pangea.services import AuthZ

        PANGEA_TOKEN = os.getenv("PANGEA_AUTHZ_TOKEN")

        authz_config = PangeaConfig(domain="aws.us.pangea.cloud")

        # Setup Pangea AuthZ service client
        authz = AuthZ(token=PANGEA_TOKEN, config=authz_config)
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
             authz = AuthZ(token="pangea_token", config=config)
        """

        super().__init__(token, config, logger_name, config_id=config_id)

    def tuple_create(self, tuples: list[Tuple]) -> PangeaResponse[TupleCreateResult]:
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
            response = authz.tuple_create(
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
        return self.request.post("v1/tuple/create", TupleCreateResult, data=input_data.model_dump(exclude_none=True))

    def tuple_list(
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
            authz.tuple_list(TupleListFilter(subject_type="user", subject_id="user_1"))
        """
        input_data = TupleListRequest(
            filter=filter.model_dump(exclude_none=True), size=size, last=last, order=order, order_by=order_by
        )
        return self.request.post("v1/tuple/list", TupleListResult, data=input_data.model_dump(exclude_none=True))

    def tuple_delete(self, tuples: list[Tuple]) -> PangeaResponse[TupleDeleteResult]:
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
            response = authz.tuple_delete(
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
        return self.request.post("v1/tuple/delete", TupleDeleteResult, data=input_data.model_dump(exclude_none=True))

    def check(
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
            debug: In the event of an allowed check, return a path that granted access.
            attributes: Additional attributes for the check.

        Raises:
            PangeaAPIException: If an API Error happens.

        Returns:
            Pangea Response with the result of the check.
            Available response fields can be found in our
            [API Documentation](https://pangea.cloud/docs/api/authz#/v1/check-post).

        Examples:
            response = authz.check(
                resource=Resource(type="file", id="file_1"),
                action="update",
                subject=Subject(type="user", id="user_1"),
                debug=True,
            )
        """

        input_data = CheckRequest(resource=resource, action=action, subject=subject, debug=debug, attributes=attributes)
        return self.request.post("v1/check", CheckResult, data=input_data.model_dump(exclude_none=True))

    def list_resources(
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
            authz.list_resources(
                type="file",
                action="update",
                subject=Subject(type="user", id="user_1"),
            )
        """

        input_data = ListResourcesRequest(type=type, action=action, subject=subject, attributes=attributes)
        return self.request.post(
            "v1/list-resources", ListResourcesResult, data=input_data.model_dump(exclude_none=True)
        )

    def list_subjects(
        self, resource: Resource, action: str, attributes: dict[str, Any] | None = None, *, debug: bool | None = None
    ) -> PangeaResponse[ListSubjectsResult]:
        """List subjects.

        Given a resource and an action, return the list of subjects who have
        access to the action for the given resource.

        Args:
            resource: The resource to filter subjects.
            action: The action to filter subjects.
            attributes: A JSON object of attribute data.
            debug: Return a path for each found subject.

        Raises:
            PangeaAPIException: If an API Error happens.

        Returns:
            Pangea Response with a list of subjects.
            Available response fields can be found in our
            [API Documentation](https://pangea.cloud/docs/api/authz#/v1/list-subjects-post).

        Examples:
            response = authz.list_subjects(
                resource=Resource(type="file", id="file_1"),
                action="update",
            )
        """

        input_data = ListSubjectsRequest(resource=resource, action=action, attributes=attributes, debug=debug)
        return self.request.post("v1/list-subjects", ListSubjectsResult, data=input_data.model_dump(exclude_none=True))

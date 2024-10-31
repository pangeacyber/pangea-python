# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
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


class TupleCreateRequest(APIRequestModel):
    tuples: List[Tuple]


class TupleCreateResult(PangeaResponseResult):
    pass


class TupleListFilter(APIRequestModel):
    resource_type: Optional[str] = None
    resource_type__contains: Optional[List[str]] = None
    resource_type__in: Optional[List[str]] = None
    resource_id: Optional[str] = None
    resource_id__contains: Optional[List[str]] = None
    resource_id__in: Optional[List[str]] = None
    relation: Optional[str] = None
    relation__contains: Optional[List[str]] = None
    relation__in: Optional[List[str]] = None
    subject_type: Optional[str] = None
    subject_type__contains: Optional[List[str]] = None
    subject_type__in: Optional[List[str]] = None
    subject_id: Optional[str] = None
    subject_id__contains: Optional[List[str]] = None
    subject_id__in: Optional[List[str]] = None
    subject_action: Optional[str] = None
    subject_action__contains: Optional[List[str]] = None
    subject_action__in: Optional[List[str]] = None


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
    attributes: Optional[Dict[str, Any]] = None


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

    def tuple_create(self, tuples: List[Tuple]) -> PangeaResponse[TupleCreateResult]:
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
            authz.tuple_list(TupleListFilter(subject_type="user", subject_id="user_1"))
        """
        input_data = TupleListRequest(
            filter=filter.model_dump(exclude_none=True), size=size, last=last, order=order, order_by=order_by
        )
        return self.request.post("v1/tuple/list", TupleListResult, data=input_data.model_dump(exclude_none=True))

    def tuple_delete(self, tuples: List[Tuple]) -> PangeaResponse[TupleDeleteResult]:
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
            response = authz.list_subjects(
                resource=Resource(type="file", id="file_1"),
                action="update",
            )
        """

        input_data = ListSubjectsRequest(resource=resource, action=action, attributes=attributes)
        return self.request.post("v1/list-subjects", ListSubjectsResult, data=input_data.model_dump(exclude_none=True))

# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import enum
from typing import Any, Dict, List, Optional, Union

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
    RESOURCE_NAMESPACE = "resource_namespace"
    RESOURCE_ID = "resource_id"
    RELATION = "relation"
    SUBJECT_NAMESPACE = "subject_namespace"
    SUBJECT_ID = "subject_id"
    SUBJECT_ACTION = "subject_action"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class Resource(PangeaResponseResult):
    namespace: str
    id: Optional[str] = None


class Subject(PangeaResponseResult):
    namespace: str
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
    resource_namespace: Optional[str] = None
    resource_namespace__contains: Optional[List[str]] = None
    resource_namespace__in: Optional[List[str]] = None
    resource_id: Optional[str] = None
    resource_id__contains: Optional[List[str]] = None
    resource_id__in: Optional[List[str]] = None
    relation: Optional[str] = None
    relation__contains: Optional[List[str]] = None
    relation__in: Optional[List[str]] = None
    subject_namespace: Optional[str] = None
    subject_namespace__contains: Optional[List[str]] = None
    subject_namespace__in: Optional[List[str]] = None
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
    namespace: str
    id: str
    action: Optional[str]


class Debug(APIResponseModel):
    path: List[DebugPath]


class CheckResult(PangeaResponseResult):
    schema_id: str
    schema_version: int
    depth: int
    allowed: bool
    debug: Optional[Debug] = None


class ListResourcesRequest(APIRequestModel):
    namespace: str
    action: str
    subject: Subject


class ListResourcesResult(PangeaResponseResult):
    ids: List[str]


class ListSubjectsRequest(APIRequestModel):
    resource: Resource
    action: str


class ListSubjectsResult(PangeaResponseResult):
    subjects: List[Subject]


class AuthZ(ServiceBase):
    """AuthZ service client. (Beta)

    Provides methods to interact with the Pangea AuthZ Service.
    Documentation for the AuthZ Service API can be found at
    <https://pangea.cloud/docs/api/authz>. Note that this service is in Beta and
    is subject to change.

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

    def __init__(self, token: str, config=None, logger_name="pangea", config_id: Optional[str] = None):
        super().__init__(token, config, logger_name, config_id=config_id)

    def tuple_create(self, tuples: List[Tuple]) -> PangeaResponse[TupleCreateResult]:
        """Create tuples. (Beta)

        Create tuples in the AuthZ Service. The request will fail if there is no schema
        or the tuples do not validate against the schema.
        How to install a [Beta release](https://pangea.cloud/docs/sdk/python/#beta-releases).

        Args:
            tuples (List[Tuple]): List of tuples to be created.

        Raises:
            PangeaAPIException: If an API Error happens.

        Returns:
            Pangea Response with empty result.
            Available response fields can be found in our
            [API Documentation](https://pangea.cloud/docs/api/authz#/v1beta/tuple/create).

        Examples:
            response = authz.tuple_create(
                tuples=[
                    Tuple(
                        resource=Resource(namespace="file", id="file_1"),
                        relation="owner",
                        subject=Subject(namespace="user", id="user_1"),
                    )
                ]
            )
        """

        input_data = TupleCreateRequest(tuples=tuples)
        return self.request.post("v1beta/tuple/create", TupleCreateResult, data=input_data.dict(exclude_none=True))

    def tuple_list(
        self,
        filter: TupleListFilter,
        size: Optional[int] = None,
        last: Optional[str] = None,
        order: Optional[ItemOrder] = None,
        order_by: Optional[TupleOrderBy] = None,
    ) -> PangeaResponse[TupleListResult]:
        """List tuples. (Beta)

        Return a paginated list of filtered tuples. The filter is given in terms
        of a tuple. Fill out the fields that you want to filter. If the filter
        is empty it will return all the tuples.
        How to install a [Beta release](https://pangea.cloud/docs/sdk/python/#beta-releases).

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
            [API Documentation](https://pangea.cloud/docs/api/authz#/v1beta/tuple/list).

        Examples:
            authz.tuple_list(TupleListFilter(subject_namespace="user", subject_id="user_1"))
        """
        input_data = TupleListRequest(
            filter=filter.dict(exclude_none=True), size=size, last=last, order=order, order_by=order_by
        )
        return self.request.post("v1beta/tuple/list", TupleListResult, data=input_data.dict(exclude_none=True))

    def tuple_delete(self, tuples: List[Tuple]) -> PangeaResponse[TupleDeleteResult]:
        """Delete tuples. (Beta)

        Delete tuples in the AuthZ Service.
        How to install a [Beta release](https://pangea.cloud/docs/sdk/python/#beta-releases).

        Args:
            tuples (List[Tuple]): List of tuples to be deleted.

        Raises:
            PangeaAPIException: If an API Error happens.

        Returns:
            Pangea Response with empty result.
            Available response fields can be found in our
            [API Documentation](https://pangea.cloud/docs/api/authz#/v1beta/tuple/delete).

        Examples:
            response = authz.tuple_delete(
                tuples=[
                    Tuple(
                        resource=Resource(namespace="file", id="file_1"),
                        relation="owner",
                        subject=Subject(namespace="user", id="user_1"),
                    )
                ]
            )
        """

        input_data = TupleDeleteRequest(tuples=tuples)
        return self.request.post("v1beta/tuple/delete", TupleDeleteResult, data=input_data.dict(exclude_none=True))

    def check(
        self,
        resource: Resource,
        action: str,
        subject: Subject,
        debug: Optional[bool] = None,
        attributes: Optional[Dict[str, Union[int, str]]] = None,
    ) -> PangeaResponse[CheckResult]:
        """Perform a check request. (Beta)

        Check if a subject has permission to perform an action on the resource.
        How to install a [Beta release](https://pangea.cloud/docs/sdk/python/#beta-releases).

        Args:
            resource (Resource): The resource to check.
            action (str): The action to check.
            subject (Subject): The subject to check.
            debug (Optional[bool]): Setting this value to True will provide a detailed analysis of the check.
            attributes (Optional[Dict[str, Union[int, str]]]): Additional attributes for the check.

        Raises:
            PangeaAPIException: If an API Error happens.

        Returns:
            Pangea Response with the result of the check.
            Available response fields can be found in our
            [API Documentation](https://pangea.cloud/docs/api/authz#/v1beta/check).

        Examples:
            response = authz.check(
                resource=Resource(namespace="file", id="file_1"),
                action="update",
                subject=Subject(namespace="user", id="user_1"),
                debug=True,
            )
        """

        input_data = CheckRequest(resource=resource, action=action, subject=subject, debug=debug, attributes=attributes)
        return self.request.post("v1beta/check", CheckResult, data=input_data.dict(exclude_none=True))

    def list_resources(self, namespace: str, action: str, subject: Subject) -> PangeaResponse[ListResourcesResult]:
        """List resources. (Beta)

        Given a namespace, action, and subject, list all the resources in the
        namespace that the subject has access to the action with.
        How to install a [Beta release](https://pangea.cloud/docs/sdk/python/#beta-releases).

        Args:
            namespace (str): The namespace to filter resources.
            action (str): The action to filter resources.
            subject (Subject): The subject to filter resources.

        Raises:
            PangeaAPIException: If an API Error happens.

        Returns:
            Pangea Response with a list of resource IDs.
            Available response fields can be found in our
            [API Documentation](https://pangea.cloud/docs/api/authz#/v1beta/list-resources).

        Examples:
            authz.list_resources(
                namespace="file",
                action="update",
                subject=Subject(namespace="user", id="user_1"),
            )
        """

        input_data = ListResourcesRequest(namespace=namespace, action=action, subject=subject)
        return self.request.post("v1beta/list-resources", ListResourcesResult, data=input_data.dict(exclude_none=True))

    def list_subjects(self, resource: Resource, action: str) -> PangeaResponse[ListSubjectsResult]:
        """List subjects. (Beta)

        Given a resource and an action, return the list of subjects who have
        access to the action for the given resource.
        How to install a [Beta release](https://pangea.cloud/docs/sdk/python/#beta-releases).

        Args:
            resource (Resource): The resource to filter subjects.
            action (str): The action to filter subjects.

        Raises:
            PangeaAPIException: If an API Error happens.

        Returns:
            Pangea Response with a list of subjects.
            Available response fields can be found in our
            [API Documentation](https://pangea.cloud/docs/api/authz#/v1beta/list-subjects).

        Examples:
            response = authz.list_subjects(
                resource=Resource(namespace="file", id="file_1"),
                action="update",
            )
        """

        input_data = ListSubjectsRequest(resource=resource, action=action)
        return self.request.post("v1beta/list-subjects", ListSubjectsResult, data=input_data.dict(exclude_none=True))

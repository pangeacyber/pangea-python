# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from __future__ import annotations

import datetime
import enum
from typing import Any, Dict, List, Optional, Sequence, Union

from pangea.response import APIRequestModel, APIResponseModel, PangeaDateTime, PangeaResponseResult


class EventVerification(str, enum.Enum):
    NONE = "none"
    PASS = "pass"
    FAIL = "fail"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class Event(Dict[str, Any]):
    """
    Event to perform an auditable activity

    Auxiliary class to be compatible with older SDKs
    """

    def __init__(self, **data) -> None:
        super().__init__(**data)

    @property
    def message(self):
        return self.get("message")

    @message.setter
    def message(self, value):
        self["message"] = value

    @property
    def actor(self):
        return self.get("actor")

    @actor.setter
    def actor(self, value):
        self["actor"] = value

    @property
    def action(self):
        return self.get("action")

    @action.setter
    def action(self, value):
        self["action"] = value

    @property
    def new(self):
        return self.get("new")

    @new.setter
    def new(self, value):
        self["new"] = value

    @property
    def old(self):
        return self.get("old")

    @old.setter
    def old(self, value):
        self["old"] = value

    @property
    def status(self):
        return self.get("status")

    @status.setter
    def status(self, value):
        self["status"] = value

    @property
    def source(self):
        return self.get("source")

    @source.setter
    def source(self, value):
        self["source"] = value

    @property
    def target(self):
        return self.get("target")

    @target.setter
    def target(self, value):
        self["target"] = value

    @property
    def timestamp(self):
        return self.get("timestamp")

    @timestamp.setter
    def timestamp(self, value):
        self["timestamp"] = value

    @property
    def tenant_id(self):
        return self.get("tenant_id")

    @tenant_id.setter
    def tenant_id(self, value):
        self["tenant_id"] = value


class EventEnvelope(APIResponseModel):
    """
    Contain extra information about an event.

    Arguments:
    event -- Event describing auditable activity.
    signature -- An optional client-side signature for forgery protection.
    public_key -- The base64-encoded ed25519 public key used for the signature, if one is provided
    received_at -- A server-supplied timestamp
    """

    event: Dict[str, Any]
    signature: Optional[str] = None
    public_key: Optional[str] = None
    received_at: PangeaDateTime


class LogRequest(APIRequestModel):
    """
    Input class to perform a log action

    Arguments:
    event -- A structured event describing an auditable activity.
    verbose -- If true, be verbose in the response; include membership proof, unpublished root and consistency proof, etc.
    signature -- An optional client-side signature for forgery protection.
    public_key -- The base64-encoded ed25519 public key used for the signature, if one is provided.
    prev_root -- Unpublished root hash that was returned from the last log API call that was made. If the user does not provide prev_root, the consistency proof from the last known unpublished root will be provided.
    """

    event: Dict[str, Any]
    verbose: Optional[bool] = None
    signature: Optional[str] = None
    public_key: Optional[str] = None
    prev_root: Optional[str] = None


class LogEvent(APIRequestModel):
    """
    Event to perform a log action

    Arguments:
    event -- A structured event describing an auditable activity.
    signature -- An optional client-side signature for forgery protection.
    public_key -- The base64-encoded ed25519 public key used for the signature, if one is provided.
    """

    event: Dict[str, Any]
    signature: Optional[str] = None
    public_key: Optional[str] = None


class LogBulkRequest(APIRequestModel):
    """
    Request to perform a bulk log action

    Arguments:
    events -- A list structured events describing an auditable activity.
    verbose -- If true, be verbose in the response; include membership proof, unpublished root and consistency proof, etc.
    """

    events: List[LogEvent]
    verbose: Optional[bool] = None


class LogResult(PangeaResponseResult):
    """
    Result class after an audit log action

    envelope -- Event envelope information.
    hash -- Event envelope hash.
    unpublished_root -- The current unpublished root.
    membership_proof -- A proof for verifying the unpublished root.
    consistency_proof -- If prev_root was present in the request, this proof verifies that the new unpublished root is a continuation of the prev_root
    """

    envelope: Optional[EventEnvelope] = None
    hash: str
    unpublished_root: Optional[str] = None
    membership_proof: Optional[str] = None
    consistency_proof: Optional[List[str]] = None
    consistency_verification: EventVerification = EventVerification.NONE
    membership_verification: EventVerification = EventVerification.NONE
    signature_verification: EventVerification = EventVerification.NONE


class LogBulkResult(PangeaResponseResult):
    results: List[LogResult] = []


class SearchRestriction(APIResponseModel):
    """
    Set of restrictions when perform an audit search action

    Arguments:
    actor -- List of actors to include in search. If empty include all.
    action -- List of action to include in search. If empty include all.
    source -- List of sources to include in search. If empty include all.
    status -- List of status to include in search. If empty include all.
    target -- List of targets to include in search. If empty include all.
    """

    actor: List[str] = []
    action: List[str] = []
    source: List[str] = []
    status: List[str] = []
    target: List[str] = []


class SearchOrder(str, enum.Enum):
    ASC = "asc"
    DESC = "desc"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class SearchOrderBy(str, enum.Enum):
    ACTOR = "actor"
    ACTION = "action"
    MESSAGE = "message"
    RECEIVED_AT = "received_at"
    SOURCE = "source"
    STATUS = "status"
    TARGET = "target"
    TIMESTAMP = "timestamp"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class SearchRequest(APIRequestModel):
    """
    Input class to perform an audit search action

    Arguments:
        #: Query is a required field.
        #: The following optional qualifiers are supported:
        #:	* action:
        #:	* actor:
        #:	* message:
        #:	* new:
        #:	* old:
        #:	* status:
        #:	* target:
    query -- Natural search string; list of keywords with optional `<option>:<value>` qualifiers.
    order -- Specify the sort order of the response. "asc" or "desc".
    order_by -- Name of column to sort the results by. "message", "actor", "status", etc.
    start -- The start of the time range to perform the search on.
    end -- The end of the time range to perform the search on. All records up to the latest if left out.
    limit -- Number of audit records to include from the first page of the results.
    max_results -- Maximum number of results to return.
    search_restriction -- A list of keys to restrict the search results to. Useful for partitioning data available to the query string.
    verbose -- If true, include root, membership and consistency proofs in response.
    return_context -- Return the context data needed to decrypt secure audit events that have been redacted with format preserving encryption.
    """

    query: str
    order: Optional[SearchOrder] = None
    order_by: Optional[Union[SearchOrderBy, str]] = None
    last: Optional[str] = None
    start: Optional[str] = None
    end: Optional[str] = None
    limit: Optional[int] = None
    max_results: Optional[int] = None
    search_restriction: Optional[Dict[str, Sequence[str]]] = None
    verbose: Optional[bool] = None
    return_context: Optional[bool] = None


class RootRequest(APIRequestModel):
    """
    Input class to perform a root request action

    Arguments:

    tree_size -- The size of the tree (the number of records).
    """

    tree_size: Optional[int] = None


class Root(APIResponseModel):
    """
    Tree root information

    Arguments:
    tree_name -- The name of the Merkle Tree.
    size -- The size of the tree (the number of records).
    root_hash -- the root hash.
    url -- the URL where this root has been published.
    published_at -- The date/time when this root was published.
    consistency_proof -- Consistency proof to verify that this root is a continuation of the previous one.
    """

    tree_name: str
    size: int
    root_hash: str
    url: Optional[str] = None
    published_at: Optional[str] = None
    consistency_proof: Optional[List[str]] = None


class RootSource(str, enum.Enum):
    UNKNOWN = "unknown"
    ARWEAVE = "arweave"
    PANGEA = "pangea"


class PublishedRoot(APIResponseModel):
    """
    Published root information

    Arguments:
    size -- The size of the tree (the number of records).
    root_hash -- the root hash.
    published_at -- The date/time when this root was published.
    consistency_proof -- Consistency proof to verify that this root is a continuation of the previous one.
    source -- This should be "pangea" or "arweave"
    """

    size: int
    root_hash: str
    published_at: str
    consistency_proof: Optional[List[str]] = None
    source: RootSource = RootSource.UNKNOWN


class RootResult(PangeaResponseResult):
    """
    Result class after a root request
    """

    data: Root


class SearchEvent(APIResponseModel):
    """
    Event information received after a search request

    Arguments:
    envelope -- Event related information.
    hash -- The record's hash.
    leaf_index -- The index of the leaf of the Merkle Tree where this record was inserted.
    membership_proof -- A cryptographic proof that the record has been persisted in the log.
    consistency_verification -- Consistency verification calculated if required.
    membership_verification -- Membership verification calculated if required.
    signature_verification -- Signature verification calculated if required.
    fpe_context -- The context data needed to decrypt secure audit events that have been redacted with format preserving encryption.
    """

    envelope: EventEnvelope
    hash: str
    membership_proof: Optional[str] = None
    published: Optional[bool] = None
    leaf_index: Optional[int] = None
    consistency_verification: EventVerification = EventVerification.NONE
    membership_verification: EventVerification = EventVerification.NONE
    signature_verification: EventVerification = EventVerification.NONE
    fpe_context: Optional[str] = None


class SearchResultOutput(PangeaResponseResult):
    """
    Return class after a pagination search

    Arguments:
    count -- The total number of results that were returned by the search.
    events -- A list of matching audit records.
    root -- A root of a Merkle Tree.
    unpublished_root -- Root of a unpublished Merkle Tree
    """

    count: int
    events: List[SearchEvent]
    root: Optional[Root] = None
    unpublished_root: Optional[Root] = None


class SearchOutput(SearchResultOutput):
    """
    Result class after an audit search action

    Arguments:
    id -- Identifier to supply to search_results API to fetch/paginate through search results. ID is always populated on a successful response.
    expires_at -- The time when the results will no longer be available to page through via the results API.
    count -- The total number of results that were returned by the search.
    events -- A list of matching audit records.
    root -- Root of a published Merkle Tree.
    unpublished_root -- Root of a unpublished Merkle Tree
    """

    id: str
    expires_at: PangeaDateTime


class SearchResultRequest(APIRequestModel):
    """
    Class used to paginate search results

    Arguments:
    id -- A search results identifier returned by the search call.
    limit -- Number of audit records to include from the first page of the results.
    offset -- Offset from the start of the result set to start returning results from.
    assert_search_restriction -- Assert the requested search results were queried with the exact same search restrictions, to ensure the results comply to the expected restrictions.
    return_context -- Return the context data needed to decrypt secure audit events that have been redacted with format preserving encryption.
    """

    id: str
    limit: Optional[int] = 20
    offset: Optional[int] = 0
    assert_search_restriction: Optional[Dict[str, Sequence[str]]] = None
    return_context: Optional[bool] = None


class DownloadFormat(str, enum.Enum):
    JSON = "json"
    """JSON."""

    CSV = "csv"
    """CSV."""

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class DownloadRequest(APIRequestModel):
    request_id: Optional[str] = None
    """ID returned by the export API."""

    result_id: Optional[str] = None
    """ID returned by the search API."""

    format: Optional[str] = None
    """Format for the records."""

    return_context: Optional[bool] = None
    """Return the context data needed to decrypt secure audit events that have been redacted with format preserving encryption."""


class DownloadResult(PangeaResponseResult):
    dest_url: str
    """URL where search results can be downloaded."""

    expires_at: str
    """
    The time when the results will no longer be available to page through via
    the results API.
    """


class ExportRequest(APIRequestModel):
    format: DownloadFormat = DownloadFormat.CSV
    """Format for the records."""

    start: Optional[datetime.datetime] = None
    """The start of the time range to perform the search on."""

    end: Optional[datetime.datetime] = None
    """
    The end of the time range to perform the search on. If omitted, then all
    records up to the latest will be searched.
    """

    order_by: Optional[str] = None
    """Name of column to sort the results by."""

    order: Optional[SearchOrder] = None
    """Specify the sort order of the response."""

    verbose: bool = True
    """
    Whether or not to include the root hash of the tree and the membership proof
    for each record.
    """

# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import copy
import datetime
import enum
import json
from typing import List, Optional, Union

from pangea.response import APIRequestModel, APIResponseModel, PangeaResponseResult


class EventVerification(str, enum.Enum):
    NONE = "none"
    PASS = "pass"
    FAIL = "fail"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class EventSigning(enum.Enum):
    NONE = 0
    LOCAL = 1

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class Event(APIResponseModel):
    """Event to perform an auditable activity

    Arguments:
    message -- A message describing a detailed account of what happened.
    actor -- who performed the auditable activity.
    action -- auditable action that occurred.
    new -- The value of a record after it was changed.
    old -- The value of a record before it was changed.
    source -- Used to record the location from where an activity occurred.
    status -- Record whether or not the activity was successful.
    target -- Used to record the specific record that was targeted by the auditable activity.
    timestamp -- An optional client-supplied timestamp.
    """

    message: Union[str, dict]
    actor: Optional[str] = None
    action: Optional[str] = None
    new: Optional[Union[str, dict]] = None
    old: Optional[Union[str, dict]] = None
    source: Optional[str] = None
    status: Optional[str] = None
    target: Optional[str] = None
    timestamp: Optional[datetime.datetime] = None

    _JSON_SUPPORTED_FIELDS = ["message", "new", "old"]

    def __init__(self, **data):
        super().__init__(**data)
        self.parse_json_fields()

    def parse_json_fields(self):
        """Parse JSON supported fields from string to dict"""
        for f in self._JSON_SUPPORTED_FIELDS:
            v = getattr(self, f)
            if type(v) is str:
                try:
                    obj = json.loads(v)
                    setattr(self, f, obj)
                except:
                    pass

    def get_stringified_copy(self):
        """Return object copy with JSON supported fields in string format"""
        aux = copy.deepcopy(self)
        for f in self._JSON_SUPPORTED_FIELDS:
            v = getattr(aux, f, None)
            if v is not None and type(v) is dict:
                setattr(aux, f, self._dict_to_canonicalized_str(v))
        return aux

    def _dict_to_canonicalized_str(self, message: dict) -> str:
        """Convert dict to canonical str"""
        return json.dumps(message, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


class EventEnvelope(APIResponseModel):
    """
    Contain extra information about an event.

    Arguments:
    event -- Event describing auditable activity.
    signature -- An optional client-side signature for forgery protection.
    public_key -- The base64-encoded ed25519 public key used for the signature, if one is provided
    received_at -- A server-supplied timestamp
    """

    event: Event
    signature: Optional[str] = None
    public_key: Optional[str] = None
    received_at: datetime.datetime


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

    event: Event
    verbose: Optional[bool] = None
    signature: Optional[str] = None
    public_key: Optional[str] = None
    prev_root: Optional[str] = None


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


class SearchRestriction(APIResponseModel):
    """
    Set of restrictions when perform an audit search action

    Arguments:
    actor -- List of actors to include in search. If empty include all.
    action -- List of action to include in search. If empty include all.
    source -- List of sourcers to include in search. If empty include all.
    status -- List of status to include in search. If empty include all.
    target -- List of targets to include in search. If empty include all.
    """

    actor: List[str] = []
    action: List[str] = []
    source: List[str] = []
    status: List[str] = []
    target: List[str] = []


class SearchOrder(str, enum.Enum):
    ASC = "desc"
    DESC = "asc"


class SearchOrderBy(str, enum.Enum):
    ACTOR = "actor"
    ACTION = "action"
    MESSAGE = "message"
    RECEIVED_AT = "received_at"
    SOURCE = "source"
    STATUS = "status"
    TARGET = "target"
    TIMESTAMP = "timestamp"


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
    """

    query: str
    order: Optional[SearchOrder] = None
    order_by: Optional[SearchOrderBy] = None
    last: Optional[str] = None
    start: Optional[str] = None
    end: Optional[str] = None
    limit: Optional[int] = None
    max_results: Optional[int] = None
    search_restriction: Optional[dict] = None
    verbose: Optional[bool] = None


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
    """

    envelope: EventEnvelope
    hash: str
    membership_proof: Optional[str] = None
    published: Optional[bool] = None
    leaf_index: Optional[int] = None
    consistency_verification: EventVerification = EventVerification.NONE
    membership_verification: EventVerification = EventVerification.NONE
    signature_verification: EventVerification = EventVerification.NONE


class SearchOutput(PangeaResponseResult):
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

    count: int
    events: List[SearchEvent]
    id: str
    expires_at: datetime.datetime
    root: Optional[Root] = None
    unpublished_root: Optional[Root] = None


class SearchResultRequest(APIRequestModel):
    """
    Class used to paginate search results

    Arguments:
    id -- A search results identifier returned by the search call.
    limit -- Number of audit records to include from the first page of the results.
    offset -- Offset from the start of the result set to start returning results from.
    """

    id: str
    limit: Optional[int] = 20
    offset: Optional[int] = 0


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

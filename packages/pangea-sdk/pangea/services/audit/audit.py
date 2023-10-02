# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import datetime
import json
from typing import Any, Dict, Optional, Union

from pangea.response import PangeaResponse
from pangea.services.audit.exceptions import AuditException, EventCorruption
from pangea.services.audit.models import (
    Event,
    EventEnvelope,
    EventVerification,
    LogRequest,
    LogResult,
    PublishedRoot,
    Root,
    RootRequest,
    RootResult,
    RootSource,
    SearchEvent,
    SearchOrder,
    SearchOrderBy,
    SearchOutput,
    SearchRequest,
    SearchResultOutput,
    SearchResultRequest,
)
from pangea.services.audit.signing import Signer, Verifier
from pangea.services.audit.util import (
    canonicalize_event,
    decode_consistency_proof,
    decode_hash,
    decode_membership_proof,
    format_datetime,
    get_arweave_published_roots,
    get_public_key,
    verify_consistency_proof,
    verify_envelope_hash,
    verify_membership_proof,
)
from pangea.services.base import ServiceBase
from pangea.utils import canonicalize_nested_json


class AuditBase:
    def __init__(
        self, private_key_file: str = "", public_key_info: Dict[str, str] = {}, tenant_id: Optional[str] = None
    ):
        self.pub_roots: Dict[int, Root] = {}
        self.buffer_data: Optional[str] = None
        self.signer: Optional[Signer] = Signer(private_key_file) if private_key_file else None
        self.public_key_info = public_key_info

        # In case of Arweave failure, ask the server for the roots
        self.allow_server_roots = True
        self.prev_unpublished_root_hash: Optional[str] = None
        self.tenant_id = tenant_id

    def _pre_log_process(self, event: dict, sign_local: bool, verify: bool, verbose: bool) -> LogRequest:
        if event.get("tenant_id", None) is None and self.tenant_id:
            event["tenant_id"] = self.tenant_id

        event = {k: v for k, v in event.items() if v is not None}
        event = canonicalize_nested_json(event)

        if sign_local is True and self.signer is None:
            raise AuditException("Error: the `signing` parameter set, but `signer` is not configured")

        input = LogRequest(event=event, verbose=verbose)

        if sign_local is True:
            data2sign = canonicalize_event(event)
            signature = self.signer.sign(data2sign)
            if signature is not None:
                input.signature = signature
            else:
                raise AuditException("Error: failure signing message")

            # Add public key value to public key info and serialize
            self._set_public_key(input, self.signer, self.public_key_info)

        if verify:
            input.verbose = True
            if self.prev_unpublished_root_hash:
                input.prev_root = self.prev_unpublished_root_hash

        return input

    def handle_log_response(self, response: PangeaResponse, verify: bool) -> PangeaResponse[LogResult]:
        if not response.success:
            return response

        new_unpublished_root_hash = response.result.unpublished_root

        if verify:
            if response.result.envelope:
                # verify event hash
                if response.result.hash and not verify_envelope_hash(response.result.envelope, response.result.hash):
                    # it's a extreme case, it's OK to raise an exception
                    raise EventCorruption("Error: Event hash failed.", response.result.envelope)

                response.result.signature_verification = self.verify_signature(response.result.envelope)

            if new_unpublished_root_hash:
                if response.result.membership_proof is not None:
                    # verify membership proofs
                    membership_proof = decode_membership_proof(response.result.membership_proof)
                    if verify_membership_proof(
                        node_hash=decode_hash(response.result.hash),
                        root_hash=decode_hash(new_unpublished_root_hash),
                        proof=membership_proof,
                    ):
                        response.result.membership_verification = EventVerification.PASS
                    else:
                        response.result.membership_verification = EventVerification.FAIL

                # verify consistency proofs (following events)
                if response.result.consistency_proof is not None and self.prev_unpublished_root_hash:
                    consistency_proof = decode_consistency_proof(response.result.consistency_proof)
                    if verify_consistency_proof(
                        new_root=decode_hash(new_unpublished_root_hash),
                        prev_root=decode_hash(self.prev_unpublished_root_hash),
                        proof=consistency_proof,
                    ):
                        response.result.consistency_verification = EventVerification.PASS
                    else:
                        response.result.consistency_verification = EventVerification.FAIL

        # Update prev unpublished root
        if new_unpublished_root_hash:
            self.prev_unpublished_root_hash = new_unpublished_root_hash
        return response

    def handle_results_response(
        self, response: PangeaResponse[SearchResultOutput], verify_consistency: bool = False, verify_events: bool = True
    ) -> PangeaResponse[SearchResultOutput]:
        if not response.success:
            return response

        return self.process_search_results(response, verify_consistency, verify_events)

    def handle_search_response(
        self, response: PangeaResponse[SearchOutput], verify_consistency: bool = False, verify_events: bool = True
    ) -> PangeaResponse[SearchOutput]:
        if not response.success:
            return response

        return self.process_search_results(response, verify_consistency, verify_events)

    def process_search_results(
        self, response: PangeaResponse[SearchResultOutput], verify_consistency: bool = False, verify_events: bool = True
    ) -> PangeaResponse[SearchResultOutput]:
        if verify_events:
            for event_search in response.result.events:
                # verify event hash
                if event_search.hash and not verify_envelope_hash(event_search.envelope, event_search.hash):
                    # it's a extreme case, it's OK to raise an exception
                    raise EventCorruption(
                        f"Event hash verification failed. Received_at: {event_search.envelope.received_at}. Search again with verify_events=False to recover events",
                        event_search.envelope,
                    )

                event_search.signature_verification = self.verify_signature(event_search.envelope)

        root = response.result.root
        unpublished_root = response.result.unpublished_root

        if verify_consistency:
            self.update_published_roots(response.result)

            for search_event in response.result.events:
                # verify membership proofs
                if self.can_verify_membership_proof(search_event):
                    if self.verify_membership_proof(root if search_event.published else unpublished_root, search_event):
                        search_event.membership_verification = EventVerification.PASS
                    else:
                        search_event.membership_verification = EventVerification.FAIL

                # verify consistency proofs
                if self.can_verify_consistency_proof(search_event):
                    if self.verify_consistency_proof(self.pub_roots, search_event):
                        search_event.consistency_verification = EventVerification.PASS
                    else:
                        search_event.consistency_verification = EventVerification.FAIL

        return response

    def update_published_roots(self, result: SearchOutput):
        """Fetches series of published root hashes from Arweave

        This is used for subsequent calls to verify_consistency_proof(). Root hashes
        are published on [Arweave](https://arweave.net).

        Args:
            result (SearchOutput): PangeaResponse object from previous call to audit.search()

        Raises:
            AuditException: If an audit based api exception happens
            PangeaAPIException: If an API Error happens
        """

        if not result.root:
            return

        tree_sizes = set()
        for search_event in result.events:
            leaf_index = search_event.leaf_index
            if leaf_index is not None:
                tree_sizes.add(leaf_index + 1)
                if leaf_index > 0:
                    tree_sizes.add(leaf_index)

        tree_sizes.add(result.root.size)
        tree_sizes.difference_update(self.pub_roots.keys())

        if tree_sizes:
            arweave_roots = get_arweave_published_roots(result.root.tree_name, list(tree_sizes))  # + [result.count])
        else:
            arweave_roots = {}

        # fill the missing roots from the server (if allowed)
        for tree_size in tree_sizes:
            pub_root = None
            if tree_size in arweave_roots:
                pub_root = PublishedRoot(**arweave_roots[tree_size].dict(exclude_none=True))
                pub_root.source = RootSource.ARWEAVE
            elif self.allow_server_roots:
                resp = self.root(tree_size=tree_size)
                if resp.success:
                    pub_root = PublishedRoot(**resp.result.data.dict(exclude_none=True))
                    pub_root.source = RootSource.PANGEA
            self.pub_roots[tree_size] = pub_root

    def can_verify_membership_proof(self, event: SearchEvent) -> bool:
        """
        Can verify membership proof

        If a given event's membership within the tree can be proven.

        Read more at: [What is a membership proof?](https://pangea.cloud/docs/audit/merkle-trees#what-is-a-membership-proof)

        Args:
            event (obj): The audit event to be verified

        Returns:
            bool: True if membership proof is available, False otherwise
        """
        return event.membership_proof is not None

    def verify_membership_proof(self, root: Root, event: SearchEvent) -> bool:
        """
        Verify membership proof

        Verifies an event's membership proof within the tree.

        Read more at: [What is a membership proof?](https://pangea.cloud/docs/audit/merkle-trees#what-is-a-membership-proof)

        Args:
            root (Root): The root node used for verification
            event (SearchEvent): The audit event to be verified

        Returns:
            bool: True if membership proof is verified, False otherwise
        """
        if not self.allow_server_roots and root.source != RootSource.ARWEAVE:
            return False

        node_hash = decode_hash(event.hash)
        root_hash = decode_hash(root.root_hash)
        proof = decode_membership_proof(event.membership_proof)

        return verify_membership_proof(node_hash, root_hash, proof)

    def can_verify_consistency_proof(self, event: SearchEvent) -> bool:
        """
        Can verify consistency proof

        If a given event's consistency across time can be proven.

        Read more at: [What is a consistency proof?](https://pangea.cloud/docs/audit/merkle-trees#what-is-a-consistency-proof)

        Args:
            event (SearchEvent): The audit event to be verified.

        Returns:
            bool: True if the consistency can be verified, False otherwise
        """
        return event.published and event.leaf_index is not None and event.leaf_index >= 0

    def verify_consistency_proof(self, pub_roots: Dict[int, Root], event: SearchEvent) -> bool:
        """
        Verify consistency proof

        Checks the cryptographic consistency of the event across time.

        Read more at: [What is a consistency proof?](https://pangea.cloud/docs/audit/merkle-trees#what-is-a-consistency-proof)

        Args:
            pub_roots (dict[int, Root]): list of published root hashes across time
            event (SearchEvent): Audit event to be verified.

        Returns:
            bool: True if consistency proof is verified, False otherwise.
        """

        if event.leaf_index == 0:
            return True

        curr_root = pub_roots.get(event.leaf_index + 1)
        prev_root = pub_roots.get(event.leaf_index)

        if not curr_root or not prev_root:
            return False

        if not self.allow_server_roots and (
            curr_root.source != RootSource.ARWEAVE or prev_root.source != RootSource.ARWEAVE
        ):
            return False

        curr_root_hash = decode_hash(curr_root.root_hash)
        prev_root_hash = decode_hash(prev_root.root_hash)
        proof = decode_consistency_proof(curr_root.consistency_proof)

        return verify_consistency_proof(curr_root_hash, prev_root_hash, proof)

    def verify_signature(self, audit_envelope: EventEnvelope) -> EventVerification:
        """
        Verify signature

        Args:
            audit_envelope (EventEnvelope): Object to verify

        Returns:
          EventVerification: PASS if success, FAIL if fail or NONE in case that there is not enough information to verify it

        """
        public_key = get_public_key(audit_envelope.public_key)

        if audit_envelope and audit_envelope.signature and public_key:
            v = Verifier()
            verification = v.verify_signature(
                audit_envelope.signature, canonicalize_event(audit_envelope.event), public_key
            )
            if verification is not None:
                return EventVerification.PASS if verification else EventVerification.FAIL
            else:
                return EventVerification.NONE
        else:
            return EventVerification.NONE

    def _set_public_key(self, input: LogRequest, signer: Signer, public_key_info: Dict[str, str]):
        public_key_info["key"] = signer.get_public_key_PEM()
        public_key_info["algorithm"] = signer.get_algorithm()
        input.public_key = json.dumps(
            public_key_info, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True
        )


class Audit(ServiceBase, AuditBase):
    """Audit service client.

    Provides methods to interact with the [Pangea Audit Service](https://pangea.cloud/docs/api/audit).

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import Audit

        PANGEA_TOKEN = os.getenv("PANGEA_AUDIT_TOKEN")
        audit_config = PangeaConfig(domain="aws.us.pangea.cloud")

        # Setup Pangea Audit service
        audit = Audit(token=PANGEA_TOKEN, config=audit_config)
    """

    service_name = "audit"

    def __init__(
        self,
        token,
        config=None,
        private_key_file: str = "",
        public_key_info: Dict[str, str] = {},
        tenant_id: Optional[str] = None,
        logger_name="pangea",
        config_id: Optional[str] = None,
    ):
        # FIXME: Temporary check to deprecate config_id from PangeaConfig.
        # Delete it when deprecate PangeaConfig.config_id
        if config_id and config is not None and config.config_id is not None:
            config_id = config.config_id
        ServiceBase.__init__(self, token, config=config, logger_name=logger_name, config_id=config_id)
        AuditBase.__init__(
            self, private_key_file=private_key_file, public_key_info=public_key_info, tenant_id=tenant_id
        )

    def log(
        self,
        message: Union[str, dict],
        actor: Optional[str] = None,
        action: Optional[str] = None,
        new: Optional[Union[str, dict]] = None,
        old: Optional[Union[str, dict]] = None,
        source: Optional[str] = None,
        status: Optional[str] = None,
        target: Optional[str] = None,
        timestamp: Optional[datetime.datetime] = None,
        verify: bool = False,
        sign_local: bool = False,
        verbose: Optional[bool] = None,
    ) -> PangeaResponse[LogResult]:
        """
        Log an entry

        Create a log entry in the Secure Audit Log.

        OperationId: audit_post_v1_log

        Args:
            message (str, dict): A message describing a detailed account of what happened.
            actor (str, optional): Record who performed the auditable activity.
            action (str, optional): The auditable action that occurred.
            new (str, dict, optional): The value of a record after it was changed.
            old (str, dict, optional): The value of a record before it was changed.
            source (str, optional): Used to record the location from where an activity occurred.
            status (str, optional): Record whether or not the activity was successful.
            target (str, optional): Used to record the specific record that was targeted by the auditable activity.
            timestamp (datetime, optional): An optional client-supplied timestamp.
            verify (bool, optional): True to verify logs consistency after response.
            sign_local (bool, optional): True to sign event with local key.
            verbose (bool, optional): True to get a more verbose response.
            tenant_id (string, optional): Used to record the tenant associated with this activity.
        Raises:
            AuditException: If an audit based api exception happens
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the hash of event data and optional verbose
                results are returned in the response.result field.
                Available response fields can be found in our
                [API documentation](https://pangea.cloud/docs/api/audit#log-an-entry).

        Examples:
            try:
                log_response = audit.log(message="Hello world", verbose=False)
                print(f"Response. Hash: {log_response.result.hash}")
            except pe.PangeaAPIException as e:
                print(f"Request Error: {e.response.summary}")
                for err in e.errors:
                    print(f"\\t{err.detail} \\n")
        """

        event = Event(
            message=message,
            actor=actor,
            action=action,
            new=new,
            old=old,
            source=source,
            status=status,
            target=target,
            timestamp=timestamp,
        )

        return self.log_event(event=event, verify=verify, sign_local=sign_local, verbose=verbose)

    def log_event(
        self,
        event: Dict[str, Any],
        verify: bool = False,
        sign_local: bool = False,
        verbose: Optional[bool] = None,
    ) -> PangeaResponse[LogResult]:
        """
        Log an entry

        Create a log entry in the Secure Audit Log.
        Args:
            event (dict[str, Any]): event to be logged
            verify (bool, optional): True to verify logs consistency after response.
            sign_local (bool, optional): True to sign event with local key.
            verbose (bool, optional): True to get a more verbose response.
        Raises:
            AuditException: If an audit based api exception happens
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the hash of event data and optional verbose
                results are returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/audit#log-an-entry).

        Examples:
            try:
                log_response = audit.log({"message"="Hello world"}, verbose=False)
                print(f"Response. Hash: {log_response.result.hash}")
            except pe.PangeaAPIException as e:
                print(f"Request Error: {e.response.summary}")
                for err in e.errors:
                    print(f"\\t{err.detail} \\n")
        """

        input = self._pre_log_process(event, sign_local=sign_local, verify=verify, verbose=verbose)
        response = self.request.post("v1/log", LogResult, data=input.dict(exclude_none=True))
        return self.handle_log_response(response, verify=verify)

    def search(
        self,
        query: str,
        order: Optional[SearchOrder] = None,
        order_by: Optional[SearchOrderBy] = None,
        start: Optional[Union[datetime.datetime, str]] = None,
        end: Optional[Union[datetime.datetime, str]] = None,
        limit: Optional[int] = None,
        max_results: Optional[int] = None,
        search_restriction: Optional[dict] = None,
        verbose: Optional[bool] = None,
        verify_consistency: bool = False,
        verify_events: bool = True,
    ) -> PangeaResponse[SearchOutput]:
        """
        Search the log

        Search for events that match the provided search criteria.

        OperationId: audit_post_v1_search

        Args:
            query (str): Natural search string; list of keywords with optional
                `<option>:<value>` qualifiers. The following optional qualifiers are supported:
                    - action
                    - actor
                    - message
                    - new
                    - old
                    - status
                    - target
            order (SearchOrder, optional): Specify the sort order of the response.
            order_by (SearchOrderBy, optional): Name of column to sort the results by.
            last (str, optional): Optional[str] = None,
            start (datetime, optional): An RFC-3339 formatted timestamp, or relative time adjustment from the current time.
            end (datetime, optional): An RFC-3339 formatted timestamp, or relative time adjustment from the current time.
            limit (int, optional): Optional[int] = None,
            max_results (int, optional): Maximum number of results to return.
            search_restriction (dict, optional): A list of keys to restrict the search results to. Useful for partitioning data available to the query string.
            verbose (bool, optional): If true, response include root and membership and consistency proofs.
            verify_consistency (bool): True to verify logs consistency
            verify_events (bool): True to verify hash events and signatures

        Raises:
            AuditException: If an audit based api exception happens
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse[SearchOutput] where the first page of matched events is returned in the
                response.result field. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/audit#search-for-events).
                Pagination can be found in the [search results endpoint](https://pangea.cloud/docs/api/audit#search-results).

        Examples:
            response: PangeaResponse[SearchOutput] = audit.search(query="message:test", search_restriction={'source': ["monitor"]}, limit=1, verify_consistency=True, verify_events=True)
        """

        if verify_consistency:
            verbose = True

        input = SearchRequest(
            query=query,
            order=order,
            order_by=order_by,
            start=format_datetime(start) if isinstance(start, datetime.datetime) else start,
            end=format_datetime(end) if isinstance(end, datetime.datetime) else end,
            limit=limit,
            max_results=max_results,
            search_restriction=search_restriction,
            verbose=verbose,
        )

        response = self.request.post("v1/search", SearchOutput, data=input.dict(exclude_none=True))
        return self.handle_search_response(response, verify_consistency, verify_events)

    def results(
        self,
        id: str,
        limit: Optional[int] = 20,
        offset: Optional[int] = 0,
        verify_consistency: bool = False,
        verify_events: bool = True,
    ) -> PangeaResponse[SearchResultOutput]:
        """
        Results of a search

        Fetch paginated results of a previously executed search.

        OperationId: audit_post_v1_results

        Args:
            id (string): the id of a search action, found in `response.result.id`
            limit (integer, optional): the maximum number of results to return, default is 20
            offset (integer, optional): the position of the first result to return, default is 0
            verify_consistency (bool): True to verify logs consistency
            verify_events (bool): True to verify hash events and signatures
        Raises:
            AuditException: If an audit based api exception happens
            PangeaAPIException: If an API Error happens

        Examples:
            search_res: PangeaResponse[SearchOutput] = audit.search(
                query="message:test",
                search_restriction={'source': ["monitor"]},
                limit=100,
                verify_consistency=True,
                verify_events=True)

            result_res: PangeaResponse[SearchResultsOutput] = audit.results(
                id=search_res.result.id,
                limit=10,
                offset=0)
        """

        if limit <= 0:
            raise AuditException("The 'limit' argument must be a positive integer > 0")

        if offset < 0:
            raise AuditException("The 'offset' argument must be a positive integer")

        input = SearchResultRequest(
            id=id,
            limit=limit,
            offset=offset,
        )
        response = self.request.post("v1/results", SearchResultOutput, data=input.dict(exclude_none=True))
        return self.handle_results_response(response, verify_consistency, verify_events)

    def root(self, tree_size: Optional[int] = None) -> PangeaResponse[RootResult]:
        """
        Tamperproof verification

        Returns current root hash and consistency proof.

        OperationId: audit_post_v1_root

        Args:
            tree_size (int, optional): The size of the tree (the number of records). If None, endpoint will return last tree root.

        Returns:
            PangeaResponse[RootOutput]

        Raises:
            AuditException: If an audit based api exception happens
            PangeaAPIException: If an API Error happens

        Examples:
            response = audit.root(tree_size=7)
        """
        input = RootRequest(tree_size=tree_size)
        return self.request.post("v1/root", RootResult, data=input.dict(exclude_none=True))

# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import datetime
import json
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import pangea.exceptions as pexc
from pangea.response import PangeaResponse
from pangea.services.audit.exceptions import AuditException, EventCorruption
from pangea.services.audit.models import (
    DownloadFormat,
    DownloadRequest,
    DownloadResult,
    Event,
    EventEnvelope,
    EventVerification,
    LogBulkRequest,
    LogBulkResult,
    LogEvent,
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
        self.pub_roots: Dict[int, PublishedRoot] = {}
        self.buffer_data: Optional[str] = None
        self.signer: Optional[Signer] = Signer(private_key_file) if private_key_file else None
        self.public_key_info = public_key_info

        # In case of Arweave failure, ask the server for the roots
        self.allow_server_roots = True
        self.prev_unpublished_root_hash: Optional[str] = None
        self.tenant_id = tenant_id

    def _get_log_request(
        self, events: Union[dict, List[dict]], sign_local: bool, verify: bool, verbose: Optional[bool]
    ) -> Union[LogRequest, LogBulkResult]:
        if isinstance(events, list):
            request_events: List[LogEvent] = []
            for e in events:
                request_events.append(self._process_log(e, sign_local=sign_local))

            input = LogBulkRequest(events=request_events, verbose=verbose)

        elif isinstance(events, dict):
            log = self._process_log(events, sign_local=sign_local)
            input = LogRequest(event=log.event, signature=log.signature, public_key=log.public_key)  # type: ignore[assignment]
            input.verbose = True if verify else verbose
            if verify and self.prev_unpublished_root_hash:
                input.prev_root = self.prev_unpublished_root_hash  # type: ignore[attr-defined]

        else:
            raise AttributeError(f"events should be a dict or a list[dict] and it is {type(events)}")

        return input  # type: ignore[return-value]

    def _process_log(self, event: dict, sign_local: bool) -> LogEvent:
        if event.get("tenant_id", None) is None and self.tenant_id:
            event["tenant_id"] = self.tenant_id

        event = {k: v for k, v in event.items() if v is not None}
        event = canonicalize_nested_json(event)

        if sign_local is True and self.signer is None:
            raise AuditException("Error: the `signing` parameter set, but `signer` is not configured")

        signature = None
        pki = None
        if sign_local is True:
            data2sign = canonicalize_event(event)  # type: ignore[arg-type]
            signature = self.signer.sign(data2sign)  # type: ignore[union-attr]
            if signature is None:
                raise AuditException("Error: failure signing message")

            # Add public key value to public key info and serialize
            pki = self._get_public_key_info(self.signer, self.public_key_info)  # type: ignore[arg-type]

        return LogEvent(event=event, signature=signature, public_key=pki)

    def _process_log_result(self, result: LogResult, verify: bool):
        new_unpublished_root_hash = result.unpublished_root

        if verify:
            if result.envelope:
                # verify event hash
                if result.hash and not verify_envelope_hash(result.envelope, result.hash):
                    # it's a extreme case, it's OK to raise an exception
                    raise EventCorruption("Error: Event hash failed.", result.envelope)

                result.signature_verification = self.verify_signature(result.envelope)

            if new_unpublished_root_hash:
                if result.membership_proof is not None:
                    # verify membership proofs
                    membership_proof = decode_membership_proof(result.membership_proof)
                    if verify_membership_proof(
                        node_hash=decode_hash(result.hash),
                        root_hash=decode_hash(new_unpublished_root_hash),
                        proof=membership_proof,
                    ):
                        result.membership_verification = EventVerification.PASS
                    else:
                        result.membership_verification = EventVerification.FAIL

                # verify consistency proofs (following events)
                if result.consistency_proof is not None and self.prev_unpublished_root_hash:
                    consistency_proof = decode_consistency_proof(result.consistency_proof)
                    if verify_consistency_proof(
                        new_root=decode_hash(new_unpublished_root_hash),
                        prev_root=decode_hash(self.prev_unpublished_root_hash),
                        proof=consistency_proof,
                    ):
                        result.consistency_verification = EventVerification.PASS
                    else:
                        result.consistency_verification = EventVerification.FAIL

        # Update prev unpublished root
        if new_unpublished_root_hash:
            self.prev_unpublished_root_hash = new_unpublished_root_hash
        return

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

        return self.process_search_results(response, verify_consistency, verify_events)  # type: ignore[arg-type,return-value]

    def process_search_results(
        self, response: PangeaResponse[SearchResultOutput], verify_consistency: bool = False, verify_events: bool = True
    ) -> PangeaResponse[SearchResultOutput]:
        if verify_events:
            for event_search in response.result.events:  # type: ignore[union-attr]
                # verify event hash
                if event_search.hash and not verify_envelope_hash(event_search.envelope, event_search.hash):
                    # it's a extreme case, it's OK to raise an exception
                    raise EventCorruption(
                        f"Event hash verification failed. Received_at: {event_search.envelope.received_at}. Search again with verify_events=False to recover events",
                        event_search.envelope,
                    )

                event_search.signature_verification = self.verify_signature(event_search.envelope)

        root = response.result.root  # type: ignore[union-attr]
        unpublished_root = response.result.unpublished_root  # type: ignore[union-attr]

        if verify_consistency:
            for search_event in response.result.events:  # type: ignore[union-attr]
                # verify membership proofs
                if self.can_verify_membership_proof(search_event):
                    if self.verify_membership_proof(root if search_event.published else unpublished_root, search_event):  # type: ignore[arg-type]
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

    def _get_tree_sizes_and_roots(self, result: SearchResultOutput) -> Tuple[Set[int], Dict[int, PublishedRoot]]:
        if not result.root:
            return set(), {}

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
            arweave_roots = get_arweave_published_roots(result.root.tree_name, list(tree_sizes))
        else:
            arweave_roots = {}

        return tree_sizes, arweave_roots

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
        if not self.allow_server_roots and root.source != RootSource.ARWEAVE:  # type: ignore[attr-defined]
            return False

        node_hash = decode_hash(event.hash)
        root_hash = decode_hash(root.root_hash)
        proof = decode_membership_proof(event.membership_proof)  # type: ignore[arg-type]

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
        return event.published and event.leaf_index is not None and event.leaf_index >= 0  # type: ignore[return-value]

    def verify_consistency_proof(self, pub_roots: Dict[int, PublishedRoot], event: SearchEvent) -> bool:
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

        curr_root = pub_roots.get(event.leaf_index + 1)  # type: ignore[operator]
        prev_root = pub_roots.get(event.leaf_index)  # type: ignore[arg-type]

        if not curr_root or not prev_root:
            return False

        if not self.allow_server_roots and (
            curr_root.source != RootSource.ARWEAVE or prev_root.source != RootSource.ARWEAVE
        ):
            return False

        curr_root_hash = decode_hash(curr_root.root_hash)
        prev_root_hash = decode_hash(prev_root.root_hash)
        proof = decode_consistency_proof(curr_root.consistency_proof)  # type: ignore[arg-type]

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
                audit_envelope.signature, canonicalize_event(audit_envelope.event), public_key  # type: ignore[arg-type]
            )
            if verification is not None:
                return EventVerification.PASS if verification else EventVerification.FAIL
            else:
                return EventVerification.NONE
        else:
            return EventVerification.NONE

    def _get_public_key_info(self, signer: Signer, public_key_info: Dict[str, str]):
        public_key_info["key"] = signer.get_public_key_PEM()
        public_key_info["algorithm"] = signer.get_algorithm()
        return json.dumps(public_key_info, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True)


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
                [API documentation](https://pangea.cloud/docs/api/audit#/v1/log).

        Examples:
            log_response = audit.log(
                message="hello world",
                verbose=True,
            )
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
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/audit#/v1/log).

        Examples:
            try:
                log_response = audit.log({"message": "hello world"}, verbose=True)
                print(f"Response. Hash: {log_response.result.hash}")
            except pe.PangeaAPIException as e:
                print(f"Request Error: {e.response.summary}")
                for err in e.errors:
                    print(f"\\t{err.detail} \\n")
        """

        input = self._get_log_request(event, sign_local=sign_local, verify=verify, verbose=verbose)
        response: PangeaResponse[LogResult] = self.request.post("v1/log", LogResult, data=input.dict(exclude_none=True))
        if response.success and response.result is not None:
            self._process_log_result(response.result, verify=verify)
        return response

    def log_bulk(
        self,
        events: List[Dict[str, Any]],
        sign_local: bool = False,
        verbose: Optional[bool] = None,
    ) -> PangeaResponse[LogBulkResult]:
        """
        Log multiple entries

        Create multiple log entries in the Secure Audit Log.

        OperationId: audit_post_v2_log

        Args:
            events (List[dict[str, Any]]): events to be logged
            sign_local (bool, optional): True to sign event with local key.
            verbose (bool, optional): True to get a more verbose response.
        Raises:
            AuditException: If an audit based api exception happens
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the hash of event data and optional verbose
                results are returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/audit#/v2/log).

        Examples:
            log_response = audit.log_bulk(
                events=[{"message": "hello world"}],
                verbose=True,
            )
        """

        input = self._get_log_request(events, sign_local=sign_local, verify=False, verbose=verbose)
        response: PangeaResponse[LogBulkResult] = self.request.post(
            "v2/log", LogBulkResult, data=input.dict(exclude_none=True)
        )

        if response.success and response.result is not None:
            for result in response.result.results:
                self._process_log_result(result, verify=True)
        return response

    def log_bulk_async(
        self,
        events: List[Dict[str, Any]],
        sign_local: bool = False,
        verbose: Optional[bool] = None,
    ) -> PangeaResponse[LogBulkResult]:
        """
        Log multiple entries asynchronously

        Asynchronously create multiple log entries in the Secure Audit Log.

        Args:
            events (List[dict[str, Any]]): events to be logged
            sign_local (bool, optional): True to sign event with local key.
            verbose (bool, optional): True to get a more verbose response.
        Raises:
            AuditException: If an audit based api exception happens
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the hash of event data and optional verbose
                results are returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/audit#/v2/log_async).

        Examples:
            log_response = audit.log_bulk_async(
                events=[{"message": "hello world"}],
                verbose=True,
            )
        """

        input = self._get_log_request(events, sign_local=sign_local, verify=False, verbose=verbose)

        try:
            # Calling to v2 methods will return always a 202.
            response: PangeaResponse[LogBulkResult] = self.request.post(
                "v2/log_async", LogBulkResult, data=input.dict(exclude_none=True), poll_result=False
            )
        except pexc.AcceptedRequestException as e:
            return e.response

        if response.success and response.result is not None:
            for result in response.result.results:
                self._process_log_result(result, verify=True)
        return response

    def search(
        self,
        query: str,
        order: Optional[SearchOrder] = None,
        order_by: Optional[Union[SearchOrderBy, str]] = None,
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
            order_by (SearchOrderBy, str, optional): Name of column to sort the results by.
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
                response.result field. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/audit#/v1/search).
                Pagination can be found in the [search results endpoint](https://pangea.cloud/docs/api/audit#/v1/results).

        Examples:
            response = audit.search(
                query="message:test",
                search_restriction={'source': ["monitor"]},
                limit=1,
                verify_consistency=True,
                verify_events=True,
            )
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

        response: PangeaResponse[SearchOutput] = self.request.post(
            "v1/search", SearchOutput, data=input.dict(exclude_none=True)
        )
        if verify_consistency and response.result is not None:
            self.update_published_roots(response.result)
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
            response = audit.results(
                id="pas_sqilrhruwu54uggihqj3aie24wrctakr",
                limit=10,
                offset=0,
            )
        """

        if limit <= 0:  # type: ignore[operator]
            raise AuditException("The 'limit' argument must be a positive integer > 0")

        if offset < 0:  # type: ignore[operator]
            raise AuditException("The 'offset' argument must be a positive integer")

        input = SearchResultRequest(
            id=id,
            limit=limit,
            offset=offset,
        )
        response: PangeaResponse[SearchResultOutput] = self.request.post(
            "v1/results", SearchResultOutput, data=input.dict(exclude_none=True)
        )
        if verify_consistency and response.result is not None:
            self.update_published_roots(response.result)
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

    def download_results(
        self, result_id: str, format: Optional[DownloadFormat] = None
    ) -> PangeaResponse[DownloadResult]:
        """
        Download search results

        Get all search results as a compressed (gzip) CSV file.

        OperationId: audit_post_v1_download_results

        Args:
            result_id: ID returned by the search API.
            format: Format for the records.

        Returns:
            URL where search results can be downloaded.

        Raises:
            AuditException: If an Audit-based API exception occurs.
            PangeaAPIException: If an API exception occurs.

        Examples:
            response = audit.download_results(
                result_id="pas_[...]",
                format=DownloadFormat.JSON,
            )
        """

        input = DownloadRequest(result_id=result_id, format=format)
        return self.request.post("v1/download_results", DownloadResult, data=input.dict(exclude_none=True))

    def update_published_roots(self, result: SearchResultOutput):
        """Fetches series of published root hashes from Arweave

        This is used for subsequent calls to verify_consistency_proof(). Root hashes
        are published on [Arweave](https://arweave.net).

        Args:
            result (SearchResultOutput): Result object from previous call to Audit.search() or Audit.results()

        Raises:
            AuditException: If an audit based api exception happens
            PangeaAPIException: If an API Error happens
        """

        if not result.root:
            return

        tree_sizes, arweave_roots = self._get_tree_sizes_and_roots(result)

        # fill the missing roots from the server (if allowed)
        for tree_size in tree_sizes:
            pub_root = None
            if tree_size in arweave_roots:
                pub_root = PublishedRoot(**arweave_roots[tree_size].dict(exclude_none=True))
                pub_root.source = RootSource.ARWEAVE
            elif self.allow_server_roots:
                resp = self.root(tree_size=tree_size)
                if resp.success and resp.result is not None:
                    pub_root = PublishedRoot(**resp.result.data.dict(exclude_none=True))
                    pub_root.source = RootSource.PANGEA
            if pub_root is not None:
                self.pub_roots[tree_size] = pub_root

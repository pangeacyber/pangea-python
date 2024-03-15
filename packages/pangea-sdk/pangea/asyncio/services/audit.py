# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import datetime
from typing import Any, Dict, List, Optional, Union

import pangea.exceptions as pexc
from pangea.asyncio.services.base import ServiceBaseAsync
from pangea.response import PangeaResponse
from pangea.services.audit.audit import AuditBase
from pangea.services.audit.exceptions import AuditException
from pangea.services.audit.models import (
    DownloadFormat,
    DownloadRequest,
    DownloadResult,
    Event,
    LogBulkResult,
    LogResult,
    PublishedRoot,
    RootRequest,
    RootResult,
    RootSource,
    SearchOrder,
    SearchOrderBy,
    SearchOutput,
    SearchRequest,
    SearchResultOutput,
    SearchResultRequest,
)
from pangea.services.audit.util import format_datetime


class AuditAsync(ServiceBaseAsync, AuditBase):
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
        ServiceBaseAsync.__init__(self, token, config=config, logger_name=logger_name, config_id=config_id)
        AuditBase.__init__(
            self, private_key_file=private_key_file, public_key_info=public_key_info, tenant_id=tenant_id
        )

    async def log(
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

        return await self.log_event(event=event, verify=verify, sign_local=sign_local, verbose=verbose)

    async def log_event(
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

        input = self._get_log_request(event, sign_local=sign_local, verify=verify, verbose=verbose)
        response: PangeaResponse[LogResult] = await self.request.post(
            "v1/log", LogResult, data=input.dict(exclude_none=True)
        )
        if response.success and response.result is not None:
            self._process_log_result(response.result, verify=verify)
        return response

    async def log_bulk(
        self,
        events: List[Dict[str, Any]],
        sign_local: bool = False,
        verbose: Optional[bool] = None,
    ) -> PangeaResponse[LogBulkResult]:
        """
        Log an entry

        Create a log entry in the Secure Audit Log.
        Args:
            events (List[dict[str, Any]]): events to be logged
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
            FIXME:
        """

        input = self._get_log_request(events, sign_local=sign_local, verify=False, verbose=verbose)
        response: PangeaResponse[LogBulkResult] = await self.request.post(
            "v2/log", LogBulkResult, data=input.dict(exclude_none=True)
        )
        if response.success and response.result is not None:
            for result in response.result.results:
                self._process_log_result(result, verify=True)
        return response

    async def log_bulk_async(
        self,
        events: List[Dict[str, Any]],
        sign_local: bool = False,
        verbose: Optional[bool] = None,
    ) -> PangeaResponse[LogBulkResult]:
        """
        Log an entry

        Create a log entry in the Secure Audit Log.
        Args:
            events (List[dict[str, Any]]): events to be logged
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
            FIXME:
        """

        input = self._get_log_request(events, sign_local=sign_local, verify=False, verbose=verbose)
        try:
            response: PangeaResponse[LogBulkResult] = await self.request.post(
                "v2/log_async", LogBulkResult, data=input.dict(exclude_none=True), poll_result=False
            )
        except pexc.AcceptedRequestException as e:
            return e.response
        if response.success and response.result:
            for result in response.result.results:
                self._process_log_result(result, verify=True)
        return response

    async def search(
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

        response: PangeaResponse[SearchOutput] = await self.request.post(
            "v1/search", SearchOutput, data=input.dict(exclude_none=True)
        )
        if verify_consistency:
            await self.update_published_roots(response.result)  # type: ignore[arg-type]

        return self.handle_search_response(response, verify_consistency, verify_events)

    async def results(
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

        if limit <= 0:  # type: ignore[operator]
            raise AuditException("The 'limit' argument must be a positive integer > 0")

        if offset < 0:  # type: ignore[operator]
            raise AuditException("The 'offset' argument must be a positive integer")

        input = SearchResultRequest(
            id=id,
            limit=limit,
            offset=offset,
        )
        response = await self.request.post("v1/results", SearchResultOutput, data=input.dict(exclude_none=True))
        if verify_consistency and response.result is not None:
            await self.update_published_roots(response.result)

        return self.handle_results_response(response, verify_consistency, verify_events)

    async def root(self, tree_size: Optional[int] = None) -> PangeaResponse[RootResult]:
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
        return await self.request.post("v1/root", RootResult, data=input.dict(exclude_none=True))

    async def download_results(
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
            response = await audit.download_results(
                result_id="pas_[...]",
                format=DownloadFormat.JSON,
            )
        """

        input = DownloadRequest(result_id=result_id, format=format)
        return await self.request.post("v1/download_results", DownloadResult, data=input.dict(exclude_none=True))

    async def update_published_roots(self, result: SearchResultOutput):
        """Fetches series of published root hashes from Arweave

        This is used for subsequent calls to verify_consistency_proof(). Root hashes
        are published on [Arweave](https://arweave.net).

        Args:
            result (SearchResultOutput): Result object from previous call to AuditAsync.search() or AuditAsync.results()

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
                resp = await self.root(tree_size=tree_size)
                if resp.success and resp.result is not None:
                    pub_root = PublishedRoot(**resp.result.data.dict(exclude_none=True))
                    pub_root.source = RootSource.PANGEA
            if pub_root is not None:
                self.pub_roots[tree_size] = pub_root

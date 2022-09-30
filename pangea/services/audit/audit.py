# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import json
import os
from typing import Dict, List, Optional

from pangea.response import PangeaResponse
from pangea.services.audit.exceptions import AuditException, EventCorruption
from pangea.services.audit.models import *
from pangea.services.audit.signing import Signer, Verifier
from pangea.services.audit.util import (
    b64encode_ascii,
    canonicalize_event,
    decode_buffer_root,
    decode_consistency_proof,
    decode_hash,
    decode_membership_proof,
    get_arweave_published_roots,
    get_root_filename,
    verify_consistency_proof,
    verify_envelope_hash,
    verify_membership_proof,
)
from pangea.services.base import ServiceBase

SupportedFields = [
    "actor",
    "action",
    "status",
    "source",
    "target",
]

SupportedJSONFields = [
    "message",
    "new",
    "old",
]


class Audit(ServiceBase):
    """Audit service client.

    Provides methods to interact with the [Pangea Audit Service](/docs/api/audit).

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.dev.pangea.cloud/project/tokens](https://console.dev.pangea.cloud/project/tokens)
        AUDIT_CONFIG_ID - Configuration ID which can be found on the Pangea
            User Console at [https://console.dev.pangea.cloud/service/audit](https://console.dev.pangea.cloud/service/audit)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import Audit

        PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")
        AUDIT_CONFIG_ID = os.getenv("AUDIT_CONFIG_ID")

        audit_config = PangeaConfig(domain="pangea.cloud", config_id=AUDIT_CONFIG_ID)

        # Setup Pangea Audit service
        audit = Audit(token=PANGEA_TOKEN, config=audit_config)
    """

    service_name: str = "audit"
    version: str = "v1"
    config_id_header: str = "X-Pangea-Audit-Config-ID"

    def __init__(
        self,
        token,
        config=None,
        private_key_file: str = "",
    ):
        super().__init__(token, config)

        self.pub_roots: Dict[int, Root] = {}
        self.buffer_data: Optional[str] = None
        self.root_id_filename: str = get_root_filename()

        self.signer: Optional[Signer] = Signer(private_key_file) if private_key_file else None

        # In case of Arweave failure, ask the server for the roots
        self.allow_server_roots = True

    def log(
        self, event: Event, verify: bool = False, signing: bool = False, verbose: bool = False
    ) -> PangeaResponse[LogOutput]:
        """
        Log an entry

        Create a log entry in the Secure Audit Log.

        Args:
            event (Event): A structured dict describing an auditable activity.
            verify (bool, optional):
            signing (bool, optional):
            verbose (bool, optional):

        Raises:
            AuditException: If an audit based api exception happens
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the hash of event data and optional verbose
                results are returned in the response.result field.
                Available response fields can be found in our [API documentation](/docs/api/audit#log-an-entry).

        Examples:
            audit_data = {
                "action": "add_employee",
                "actor": "Mariah Carey",
                "target": "mariah@mariahcarey.com",
                "status": "success",
                "message": "Resume accepted",
                "new": { "status": "employed" },
                "source": "web",
            }

            response = audit.log(event=audit_data)

            \"\"\"
            response contains:
            {
                "request_id": "prq_ttd3wa7pm4fbut73tlc2r7gi5tcelfcq",
                "request_time": "2022-07-06T23:46:57.537Z",
                "response_time": "2022-07-06T23:46:57.556Z",
                "status": "success",
                "result": {
                    "hash": "eba9cd62d2f765a462b6a1c246e18dcb20411c5ee6f6ba4b6d315f455fdfb38a"
                },
                "summary": "Logged 1 record(s)"
            }
            \"\"\"
        """

        endpoint_name = "log"

        if signing and self.signer is None:
            raise AuditException("Error: the `signing` parameter set, but `signer` is not configured")

        input = LogInput(event=event.get_stringified_copy(), verbose=verbose, return_hash=True)

        if signing:
            data2sign = canonicalize_event(event)
            signature = self.signer.signMessage(data2sign)
            if signature is not None:
                input.signature = signature
            else:
                raise AuditException("Error: failure signing message")

            public_bytes = self.signer.getPublicKeyBytes()
            input.public_key = b64encode_ascii(public_bytes)

        prev_buffer_root = None
        if verify:
            input.verbose = True
            input.return_hash = True
            input.return_proof = True

            local_data: dict = {}
            raw_local_data = self.get_local_data()
            if raw_local_data:
                local_data = json.loads(raw_local_data)
                if local_data:
                    prev_buffer_root = local_data.get("last_root")
                    # peding_roots = buffer_data.get("pending_roots")

                    if prev_buffer_root:
                        input.prev_root = prev_buffer_root

                    # if peding_roots:
                    #     input.return_commit_proofs = peding_roots

        response = self.request.post(endpoint_name, data=input.dict(exclude_none=True))

        return self.handle_log_response(response, verify=verify, prev_buffer_root_enc=prev_buffer_root)

    def handle_log_response(
        self, response: PangeaResponse, verify: bool, prev_buffer_root_enc: bytes
    ) -> PangeaResponse[LogOutput]:
        if not response.success:
            return response

        response.result = LogOutput(**response.raw_result)

        if verify:
            new_buffer_root_enc = response.result.unpublished_root
            membership_proof_enc = response.result.membership_proof
            consistency_proof_enc = response.result.consistency_proof
            # commit_proofs = response.result.get("commit_proofs")
            event_hash_enc = response.result.hash

            new_buffer_root = decode_buffer_root(new_buffer_root_enc)
            event_hash = decode_hash(event_hash_enc)
            membership_proof = decode_membership_proof(membership_proof_enc)
            pending_roots = []

            # verify event hash
            if not verify_envelope_hash(response.result.envelope, response.result.hash):
                # it's a extreme case, it's OK to raise an exception
                raise EventCorruption(f"Error: Event hash failed.", response.result.envelope)

            # verify membership proofs
            if verify_membership_proof(
                node_hash=event_hash, root_hash=new_buffer_root.root_hash, proof=membership_proof
            ):
                response.result.membership_verification = EventVerification.PASS
            else:
                response.result.membership_verification = EventVerification.FAIL

            # verify consistency proofs (following events)
            if consistency_proof_enc:
                prev_buffer_root = decode_buffer_root(prev_buffer_root_enc)
                consistency_proof = decode_consistency_proof(consistency_proof_enc)

                if verify_consistency_proof(
                    new_root=new_buffer_root.root_hash, prev_root=prev_buffer_root.root_hash, proof=consistency_proof
                ):
                    response.result.consistency_verification = EventVerification.PASS
                else:
                    response.result.consistency_verification = EventVerification.FAIL

            # TODO: commit proofs pending yet
            # if commit_proofs:
            #     # Get the root from the cold tree...
            #     # FIXME: This should be on LogOutput by default
            #     root_response = self.root()
            #     if not root_response.success:
            #         return root_response

            #     cold_root_hash_enc = root_response.result.data.get("root_hash")
            #     if cold_root_hash_enc:
            #         cold_root_hash = decode_hash(cold_root_hash_enc)

            #         for buffer_root_enc, commit_proof_enc in commit_proofs.items():
            #             if commit_proof_enc is None:
            #                 pending_roots.append(buffer_root_enc)
            #             else:
            #                 buffer_root = decode_buffer_root(buffer_root_enc)
            #                 commit_proof = decode_consistency_proof(commit_proof_enc)

            #                 if not verify_consistency_proof(
            #                     new_root=cold_root_hash, prev_root=buffer_root.root_hash, proof=commit_proof
            #                 ):
            #                     raise AuditException(f"Error: Consistency proof failed.")

            self.set_local_data(last_root_enc=new_buffer_root_enc, pending_roots=pending_roots)

        return response

    def search(
        self,
        input: SearchInput,
        verify_consistency: bool = False,
        verify_events: bool = True,
    ) -> PangeaResponse[SearchOutput]:
        """
        Search for events

        Search for events that match the provided search criteria.

        Args:
            input (SearchInput): Input class with search query parameters
            verify (bool, optional): If set, the consistency and membership proofs are validated for all
                events returned by `search` and `results`. The fields `consistency_proof_verification` and
                `membership_proof_verification` are added to each event, with the value `pass`, `fail` or `none`.
            verify_signatures (bool, optional):

        Raises:
            AuditException: If an audit based api exception happens
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the first page of matched events is returned in the
                response.result field. Available response fields can be found in our [API documentation](/docs/api/audit#search-for-events).
                Pagination can be found in the [search results endpoint](/docs/api/audit#search-results).

        Examples:
            response = audit.search("Resume accepted", page_size=10)

            \"\"\"
            response.result contains:
            {
                'count': 1,
                'events': [
                    {
                        'envelope': {
                            'event': {
                                'action': 'reboot',
                                'actor': 'villain',o
                                'message': 'test',
                                'source': 'monitor',
                                'status': 'error',
                                'target': 'world'
                            },
                            'received_at': '2022-09-03T02:24:46.554034+00:00',
                            'membership_verification': 'pass',
                            'consistency_verification': 'pass'
                        },
                        'hash': '735b4c5d5fdbf49a680fe82b5447ca454f8bf37a607dbce9b51c45855528475b',
                        'leaf_index': 5,
                        'membership_proof': 'l:3a78ee8f8a4720dc6a832c96531a9287327b2e615f0272361211e40ff8a5431e,l:744fe2bcd44de81d96360b8839f0166dd7c400b9d283df2a089a962d41cef994,l:caeffdf1a19e3273227969f9332eb48c96e937e753d9d95ccf14902b06336c48,l:25d8e95b8392130c455d2bf8e709225891c554773f30aacf0b9ea35848d0f201'
                    }
                ],
                'expires_at': '2022-09-08T15:57:52.474234Z',
                'id': 'pit_kgr66t3yluqqexahxzdldqatirommhbt',
                'root': {
                    'consistency_proof': [
                        'x:caeffdf1a19e3273227969f9332eb48c96e937e753d9d95ccf14902b06336c48,r:59b722c11cfd1435e2a9538091022d995d0311d3f5379118dfda3fa1f04ef175,l:25d8e95b8392130c455d2bf8e709225891c554773f30aacf0b9ea35848d0f201',
                        'x:25d8e95b8392130c455d2bf8e709225891c554773f30aacf0b9ea35848d0f201,r:cd666f188d4fd8b51b3df33b65c5d2e5b9a269b9d7d324ba344cdaa62541675b'
                    ],
                    'published_at': '2022-09-03T03:02:13.848781Z',
                    'root_hash': 'dbfd18fa07ddb1210d80c428e9087e5daf4f360ac7c16b68a0b9757551ff9290',
                    'size': 6,
                    'tree_name': 'a6d48322aa88e25ede9cbac403110bf12580f11fe4cae6a8a4539950f5c236b1',
                    'url': 'https://arweave.net/P18k8w7uRt9uDMCTJ9dlvSQta1DsbOYCefboHEjzlM8'
                }
            }
            \"\"\"
        """

        endpoint_name = "search"

        # Will be removed soon
        input.include_hash = True

        if verify_consistency:
            input.include_root = True
            input.include_membership_proof = True

        response = self.request.post(endpoint_name, data=input.dict(exclude_none=True))
        return self.handle_search_response(response, verify_events)

    def results(
        self, input: SearchResultInput, verify_consistency: bool = False, verify_events: bool = True
    ) -> PangeaResponse[SearchResultOutput]:
        """
        Results of a Search

        Returns paginated results of a previous Search

        Args:
            id (string, required): the id of a search action, found in `response.result.id`
            limit (integer, optional): the maximum number of results to return, default is 20
            offset (integer, optional): the position of the first result to return, default is 0
            verify_signatures (bool, optional):

        Raises:
            AuditException: If an audit based api exception happens
            PangeaAPIException: If an API Error happens

        """

        endpoint_name = "results"

        if input.limit <= 0:
            raise AuditException("The 'limit' argument must be a positive integer > 0")

        if input.offset < 0:
            raise AuditException("The 'offset' argument must be a positive integer")

        response = self.request.post(endpoint_name, data=input.dict(exclude_none=True))
        return self.handle_search_response(response, verify_consistency, verify_events)

    def handle_search_response(
        self, response: PangeaResponse, verify_consistency: bool = False, verify_events: bool = True
    ) -> PangeaResponse[SearchOutput]:
        if not response.success:
            return response

        response.result = SearchOutput(**response.raw_result)

        if verify_events:
            for event_search in response.result.events:
                # verify event hash
                if event_search.hash and not verify_envelope_hash(event_search.envelope, event_search.hash):
                    # it's a extreme case, it's OK to raise an exception
                    raise EventCorruption(f"Error: Event hash failed.", event_search.envelope)

                event_search.signature_verification = self.verify_signature(event_search.envelope)

        root = response.result.root

        if verify_consistency:
            # if there is no root, we don't have any record migrated to cold. We cannot verify any proof
            if not root:
                return response

            self.update_published_roots(self.pub_roots, response.result)

            for search_event in response.result.events:
                # verify membership proofs
                if self.can_verify_membership_proof(search_event):
                    if self.verify_membership_proof(response.result.root, search_event):
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

    def update_published_roots(self, pub_roots: Dict[int, Optional[Root]], result: SearchOutput):
        """Fetches series of published root hashes from Arweave

        This is used for subsequent calls to verify_consistency_proof(). Root hashes
        are published on [Arweave](https://arweave.net).

        Args:
            pub_roots (dict): series of published root hashes.
            result (obj): PangeaResponse object from previous call to audit.search()

        Raises:
            AuditException: If an audit based api exception happens
            PangeaAPIException: If an API Error happens

        """
        tree_sizes = set()
        for search_event in result.events:
            leaf_index = search_event.leaf_index
            if leaf_index is not None:
                tree_sizes.add(leaf_index + 1)
                if leaf_index > 0:
                    tree_sizes.add(leaf_index)

        if result.root:
            tree_sizes.add(result.root.size)

        tree_sizes.difference_update(pub_roots.keys())
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
                resp = self.root(RootInput(tree_size=tree_size))
                if resp.success:
                    pub_root = PublishedRoot(**resp.result.data.dict(exclude_none=True))
                    pub_root.source = RootSource.PANGEA
            pub_roots[tree_size] = pub_root

    def can_verify_membership_proof(self, event: SearchEvent) -> bool:
        """
        Can verify membership proof

        If a given event's membership within the tree can be proven.

        Read more at: [What is a membership proof?](/docs/audit/merkle-trees#what-is-a-membership-proof)

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

        Read more at: [What is a membership proof?](/docs/audit/merkle-trees#what-is-a-membership-proof)

        Args:
            root (obj): The root node used for verification
            event (obj): The audit event to be verified

        Returns:
            bool: True if membership proof is verified, False otherwise
        """
        if not self.allow_server_roots and root.source != RootSource.ARWEAVE:
            return False

        # TODO: uncomment when audit created field bug is fixed
        # canon = canonicalize_json(event.event)
        # node_hash_enc = hash_data(canon)
        node_hash_enc = event.hash
        node_hash = decode_hash(node_hash_enc)
        root_hash = decode_hash(root.root_hash)

        proof = decode_membership_proof(event.membership_proof)

        return verify_membership_proof(node_hash, root_hash, proof)

    def can_verify_consistency_proof(self, event: SearchEvent) -> bool:
        """
        Can verify consistency proof

        If a given event's consistency across time can be proven.

        Read more at: [What is a consistency proof?](/docs/audit/merkle-trees#what-is-a-consistency-proof)

        Args:
            event (obj): The audit event to be verified.

        Returns:
            bool: True if the consistency can be verifed, False otherwise
        """
        leaf_index = event.leaf_index
        return leaf_index is not None and leaf_index > 0

    def verify_consistency_proof(self, pub_roots: Dict[int, Root], event: SearchEvent) -> bool:
        """
        Verify consistency proof

        Checks the cryptographic consistency of the event across time.

        Read more at: [What is a consistency proof?](/docs/audit/merkle-trees#what-is-a-consistency-proof)

        Args:
            pub_roots (dict): list of published root hashes across time
            event (obj): Audit event to be verified.

        Returns:
            bool: True if consistency proof is verified, False otherwise.
        """
        leaf_index = event.leaf_index
        curr_root = pub_roots.get(leaf_index + 1)
        prev_root = pub_roots.get(leaf_index)

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
          EventVerification: PASS or None in case that there is not enough information to verify it

        Raise:
          EventCorruption: If signature verification fails
        """
        v = Verifier()
        if audit_envelope.signature and audit_envelope.public_key:
            if v.verifyMessage(
                audit_envelope.signature, canonicalize_event(audit_envelope.event), audit_envelope.public_key
            ):
                return EventVerification.PASS
            else:
                raise EventCorruption(f"Error: Event signature verification failed.", audit_envelope)
        else:
            return EventVerification.NONE

    def root(self, input: RootInput) -> PangeaResponse[RootOutput]:
        """
        Retrieve tamperproof verification

        Returns current root hash and consistency proof.

        Args:
            tree_size (int): The size of the tree (the number of records)

        Returns:
            An PangeaResponse.

        Raises:
            AuditException: If an audit based api exception happens
            PangeaAPIException: If an API Error happens

        Examples:
            response = audit.root(tree_size=7)
        """
        endpoint_name = "root"
        response = self.request.post(endpoint_name, data=input.dict(exclude_none=True))
        response.result = RootOutput(**response.raw_result)
        return response

    def get_local_data(self):
        if not self.buffer_data:
            if os.path.exists(self.root_id_filename):
                try:
                    with open(self.root_id_filename, "r") as file:
                        self.buffer_data = file.read()
                except Exception:
                    raise AuditException("Error: Failed loading data file from local disk.")

        return self.buffer_data

    def set_local_data(self, last_root_enc: str, pending_roots: List[str]):
        buffer_dict = dict()
        buffer_dict["last_root"] = last_root_enc
        buffer_dict["pending_roots"] = pending_roots

        try:
            with open(self.root_id_filename, "w") as file:
                self.buffer_data = json.dumps(buffer_dict)
                file.write(self.buffer_data)
        except Exception:
            raise AuditException("Error: Failed saving data file to local disk.")

        return

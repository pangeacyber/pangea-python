# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import os
import json
import typing as t

from typing import List, Dict, Optional
from pangea.response import JSONObject, PangeaResponse
from pangea.signing import Signing

from .audit_util import (
    decode_consistency_proof,
    encode_hash,
    decode_hash,
    hash_dict,
    b64encode_ascii,
    b64decode,
    decode_membership_proof,
    get_arweave_published_roots,
    verify_consistency_proof,
    verify_membership_proof,
    verify_hash,
    decode_buffer_root,
    get_root_filename
)
from .base import ServiceBase

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

    Provides methods to interact with Pangea Audit Service:
        [https://docs.dev.pangea.cloud/docs/api/log-an-entry](https://docs.dev.pangea.cloud/docs/api/log-an-entry)

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

    def __init__(self, token, config=None, **kwargs):
        super().__init__(token, config)

        self.pub_roots: dict = {}
        self.buffer_data: Optional[str] = None
        self.root_id_filename: str = get_root_filename()

        # TODO: Document signing options
        self.verify_response: bool = kwargs.get("verify_response", False)
        self.enable_signing: bool = kwargs.get("enable_signing", False)

        if self.enable_signing:
            overwrite_keys_if_exists = kwargs.get("overwrite_keys_if_exists", False)
            hash_message = kwargs.get("hash_message", True)

            self.sign = Signing(
                overwrite_keys_if_exists=overwrite_keys_if_exists,
                hash_message=hash_message,
            )

        # In case of Arweave failure, ask the server for the roots
        self.allow_server_roots = True

    def log(self, event: dict, verify: bool = False, signing: bool = False, verbose: bool = False) -> PangeaResponse:
        """
        Log an entry

        Create a log entry in the Secure Audit Log.

        Args:
            event (dict): A structured dict describing an auditable activity.
            verify (bool, optional):
            signing (bool, optional):
            verbose (bool, optional):

        Returns:
            A PangeaResponse where the hash of event data and optional verbose
                results are returned in the response.result field.
                Available response fields can be found at:
                [https://docs.dev.pangea.cloud/docs/api/audit#log-an-entry](https://docs.dev.pangea.cloud/docs/api/audit#log-an-entry)

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
                "status_code": 200,
                "status": "success",
                "result": {
                    "hash": "eba9cd62d2f765a462b6a1c246e18dcb20411c5ee6f6ba4b6d315f455fdfb38a"
                },
                "summary": "Logged 1 record(s)"
            }
            \"\"\"
        """

        endpoint_name = "log"

        if signing and not self.enable_signing:
            raise Exception("Error: the `signing` parameter set, but `enable_signing` is not set to True")

        data: t.Dict[str, t.Any] = {"event": {}, "return_hash": True}

        for name in SupportedFields:
            if name in event:
                data["event"][name] = event[name]

        for name in SupportedJSONFields:
            if name in event:
                if isinstance(event[name], dict):
                    data["event"][name] = json.dumps(event[name])
                else:
                    data["event"][name] = event[name]

        if "message" not in data["event"]:
            raise Exception(f"Error: missing required field, no `message` provided")

        if verbose:
            data["verbose"] = True

        if signing:
            sign_envelope = self.create_signed_envelope(data["event"])
            signature = self.sign.signMessage(sign_envelope)
            if signature is not None:
                data["signature"] = signature
            else:

                raise Exception("Error: failure signing message")

            public_bytes = self.sign.getPublicKeyBytes()
            data["public_key"] = b64encode_ascii(public_bytes)

        prev_buffer_root = None
        if verify:
            data["verbose"] = verify
            data["return_hash"] = verify
            data["return_proof"] = verify

            buffer_data: dict = {}
            buffer_data = json.loads(self.get_buffer_data())
            if buffer_data:
                prev_buffer_root = buffer_data.get("last_root")
                return_commit_proofs = buffer_data.get("pending_roots")

                if prev_buffer_root:
                    data["prev_buffer_root"] = prev_buffer_root

                if return_commit_proofs:
                    data["return_commit_proofs"] = return_commit_proofs

        response = self.request.post(endpoint_name, data=data)

        return self.handle_log_response(response, verify=verify, prev_buffer_root_enc=prev_buffer_root)

    def handle_log_response(self, response: PangeaResponse, verify: bool, prev_buffer_root_enc: bytes):
        if not response.success:
            return response

        if verify:
            new_buffer_root_enc = response.result.get("buffer_root")
            membership_proof_enc = response.result.get("buffer_membership_proof")
            consistency_proof_enc = response.result.get("buffer_consistency_proof")
            commit_proofs = response.result.get("buffer_commit_proofs")
            event = response.result.get("event")
            event_hash_enc = response.result.get("hash")

            new_buffer_root = decode_buffer_root(new_buffer_root_enc)
            event_hash = decode_hash(event_hash_enc)
            membership_proof = decode_membership_proof(membership_proof_enc)
            pending_roots = []

            # verify event hash
            if not verify_hash(hash_dict(event), event_hash):
                raise Exception(f"Error: Event hash failed.")

            # verify membership proofs
            if not verify_membership_proof(node_hash=event_hash, root_hash=new_buffer_root.root_hash, proof=membership_proof):
                raise Exception(f"Error: Membership proof failed.")

            # verify consistency proofs (following events)
            if consistency_proof_enc:
                prev_buffer_root = decode_buffer_root(prev_buffer_root_enc)
                consistency_proof = decode_consistency_proof(consistency_proof_enc)

                if not verify_consistency_proof(new_root=new_buffer_root.root_hash, prev_root=prev_buffer_root.root_hash, proof=consistency_proof):
                    raise Exception(f"Error: Consistency proof failed.")

            if commit_proofs:
                # Get the root from the cold tree...
                root_response = self.root()
                if not root_response.success:
                    return root_response

                cold_root_hash_enc = root_response.result.data.get("root_hash")
                if cold_root_hash_enc:
                    cold_root_hash = decode_hash(cold_root_hash_enc)

                    for buffer_root_enc, commit_proof_enc in commit_proofs.items():
                        if commit_proof_enc is None:
                            pending_roots.append(buffer_root_enc)
                        else:
                            buffer_root = decode_buffer_root(buffer_root_enc)
                            commit_proof = decode_consistency_proof(commit_proof_enc)

                            if not verify_consistency_proof(new_root=cold_root_hash, prev_root=buffer_root.root_hash, proof=commit_proof):
                                raise Exception(f"Error: Consistency proof failed.")

            self.set_buffer_data(last_root_enc=new_buffer_root_enc, pending_roots=pending_roots)

        return response

    def search(
        self,
        query: str = "",
        restriction: dict = {},
        limit: int = 20,
        max_results: t.Optional[int] = None,
        start: str = "",
        end: str = "",
        order: str = "",
        order_by: str = "",
        verify: bool = False,
        verify_signatures: bool = False,
    ) -> PangeaResponse:
        """
        Search for events

        Search for events that match the provided search criteria.

        Args:
            query (str, optional): Natural search string; list of keywords with optional `<option>:<value>` qualifiers.
                The following optional qualifiers are supported:
                    - action:
                    - actor:
                    - message:
                    - new:
                    - old:
                    - status:
                    - target:
            restriction (dist, optional): A dict of field name/value pairs on which to restrict the search.
                If empty or not provided, matches only the default source.
            limit (int, optional): Maximum number of records to return per page. Default is 20.
            max_results (int, optional): Maximum number of records in total. Default is 10000.
            start (str, optional): The start of the time range to perform the search on.
            end (str, optional): The end of the time range to perform the search on.
                All records up to the latest if left out.
            order (str, optional): One of  "asc", "desc"
            order_by (str, optional): One of "actor", "action", "message", "received_at", "source", "status", "target", "timestamp"
            verify (bool, optional): If set, the consistency and membership proofs are validated for all
                events returned by `search` and `results`. The fields `consistency_proof_verification` and
                `membership_proof_verification` are added to each event, with the value `pass`, `fail` or `none`.
            verify_signatures (bool, optional):

        Returns:
            A PangeaResponse where the list of matched events is returned in the
                response.result field.  Available response fields can be found at:
                [https://docs.dev.pangea.cloud/docs/api/audit#search-for-events](https://docs.dev.pangea.cloud/docs/api/audit#search-for-events)

        Examples:
            response = audit.search("Resume accepted", page_size=10)

            \"\"\"
            response contains:
            {
                "request_id": "prq_cdrlelm2xm66kyeughcyokpg6y5mcewv",
                "request_time": "2022-07-06T23:49:09.034Z",
                "response_time": "2022-07-06T23:49:09.044Z",
                "status_code": 200,
                "status": "success",
                "result": {
                    "events": [
                        {
                            "event": {
                                "action": "update_employee",
                                "actor": "manager@acme.co",
                                "message": "\"{updating employee}\"",
                                "received_at": "2022-06-29T15:25:00.547967+00:00",
                                "source": "web",
                                "status": "pending",
                                "target": "jane.smith@gmail.com"
                            },
                            "hash": "df91bf7cc7500160525dc0959ef1c5387a998d1f68851058f427f5ac7ac8d4fb",
                            "leaf_index": 5,
                            "membership_proof": "r:34d9eb62de1d039870abd4a62d7e08be2ed4065c66b435f19a973beea53fefef,r:12bb5ab67c4a8a44439bfddbd93edc656f6bdddf6d61754364ba4eb845125aa4,r:47ea9cb1c54c3357ba1680d48c1ad33d29af53dcef5077d4f6d48ed7705fc09c,r:317b823fa5ca93e3d67d537863c9abe133128e9d26b5112b72be2ff8dafa6ceb,l:89ec1a955393bf1b5eefe29415eec8738bb00b974279a5d96bcbe9b5826f1905,l:c7610ea9a181ab9263d9ec0c0bb307480eb2f6a28c3065d1a02ba89f2268a934"
                        }
                    ],
                    "last": "1|1|",
                    "root": {
                    "consistency_proof": [
                        "x:89ec1a955393bf1b5eefe29415eec8738bb00b974279a5d96bcbe9b5826f1905,r:730315ba3fe23d9724bab2375105934c9097f08e12567d33aaf3ba36ef7eb750,l:c7610ea9a181ab9263d9ec0c0bb307480eb2f6a28c3065d1a02ba89f2268a934",
                        "x:c7610ea9a181ab9263d9ec0c0bb307480eb2f6a28c3065d1a02ba89f2268a934,r:639b0b5694aaeb70aa75380956f88b10e3507a67b94fb58c96986cf34b705344"
                    ],
                    "published_at": "2022-06-29T16:25:11.110758Z",
                    "root_hash": "d2da009f4778cd29b5bfec823f0952ee63bd1585139c4c09ddafb330ee84c27f",
                    "size": 6,
                    "tree_name": "ffaba963b14d03a695714c39f2d324c1ed8c482fcdcd224c57f5040867567de4",
                    "url": "https://arweave.net/tx/vUe6aAH4761WIeC8FMMSd1_51X6KLlGzJjuWYAa0u5g/data/"
                    }
                },
                "summary": "Found 1 record(s)"
            }
            \"\"\"
        """

        endpoint_name = "search"

        if not (isinstance(limit, int) and limit > 0):
            raise Exception("The 'limit' argument must be a positive integer > 0")

        self.verify_response = verify

        # TODO: allow control of `include` flags
        data = {
            "query": query,
            "include_membership_proof": True,
            "include_hash": True,
            "include_root": True,
            "limit": limit,
        }

        if start:
            data["start"] = start

        if end:
            data["end"] = end

        if restriction:
            data["search_restriction"] = restriction

        if order:
            data["order"] = order

        if order_by:
            data["order_by"] = order_by

        if max_results:
            data["max_results"] = max_results

        response = self.request.post(endpoint_name, data=data)

        if verify_signatures:
            for audit_envelope in response.result.events:
                if not self.verify_signature(audit_envelope):
                    raise Exception("signature failed")

        return self.handle_search_response(response)

    def results(self, id: str, limit: int = 20, offset: int = 0, verify_signatures: bool = False):
        """
        Results of a Search

        Returns paginated results of a previous Search

        Args:
            id (string, required): the id of a search action, found in `response.result.id`
            limit (integer, optional): the maximum number of results to return, default is 20
            offset (integer, optional): the position of the first result to return, default is 0
            verify_signatures (bool, optional):

        """

        endpoint_name = "results"

        if not id:
            raise Exception("An 'id' parameter is required")

        if not (isinstance(limit, int) and limit > 0):
            raise Exception("The 'limit' argument must be a positive integer > 0")

        if not (isinstance(offset, int) and offset >= 0):
            raise Exception("The 'offset' argument must be a positive integer")

        data = {
            "id": id,
            "limit": limit,
            "offset": offset,
        }

        response = self.request.post(endpoint_name, data=data)

        if verify_signatures:
            for audit_envelope in response.result.events:
                if not self.verify_signature(audit_envelope):
                    raise Exception("signature failed")

        return self.handle_search_response(response)

    def handle_search_response(self, response: PangeaResponse):
        if not response.success:
            return response

        root = response.result.root

        if self.verify_response:
            # if there is no root, we don't have any record migrated to cold. We cannot verify any proof
            if not root:
                response.result.root = {}

                # set verification flags for all events to `none`
                for audit in response.result.events:
                    audit.envelope.membership_verification = "none"
                    audit.envelope.consistency_verification = "none"

                return response

            self.update_published_roots(self.pub_roots, response.result)

            for audit in response.result.events:
                # verify membership proofs
                membership_verification = "none"
                if self.can_verify_membership_proof(audit):
                    if self.verify_membership_proof(response.result.root, audit):
                        membership_verification = "pass"
                    else:
                        membership_verification = "fail"

                audit.envelope.membership_verification = membership_verification

                # verify consistency proofs
                consistency_verification = "none"
                if self.can_verify_consistency_proof(audit):
                    if self.verify_consistency_proof(self.pub_roots, audit):
                        consistency_verification = "pass"
                    else:
                        consistency_verification = "fail"

                audit.envelope.consistency_verification = consistency_verification

        return response

    def update_published_roots(self, pub_roots: t.Dict[int, t.Optional[JSONObject]], result: JSONObject):
        """Fetches series of published root hashes from Arweave

        This is used for subsequent calls to verify_consistency_proof(). Root hashes
        are published on [Arweave](https://arweave.net).

        Args:
            pub_roots (dict): series of published root hashes.
            result (obj): PangeaResponse object from previous call to audit.search()
        """
        tree_sizes = set()
        for audit in result.events:
            leaf_index = audit.get("leaf_index")
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
                pub_root = JSONObject(arweave_roots[tree_size])
                pub_root.source = "arweave"
            elif self.allow_server_roots:
                resp = self.root(tree_size)
                if resp.success:
                    pub_root = resp.result.data
                    pub_root.source = "pangea"
            pub_roots[tree_size] = pub_root

    def can_verify_membership_proof(self, event: JSONObject) -> bool:
        """
        Can verify membership proof

        If a given event's membership within the tree can be proven.

        Read more at: [What is a membership proof?](https://docs.dev.pangea.cloud/docs/audit/tamperproof/tamperproof-audit-logs#what-is-a-membership-proof)

        Args:
            event (obj): The audit event to be verified

        Returns:
            bool: True if membership proof is available, False otherwise
        """
        return event.get("membership_proof") is not None

    def verify_membership_proof(self, root: JSONObject, event: JSONObject) -> bool:
        """
        Verify membership proof

        Verifies an event's membership proof within the tree.

        Read more at: [What is a membership proof?](https://docs.dev.pangea.cloud/docs/audit/tamperproof/tamperproof-audit-logs#what-is-a-membership-proof)

        Args:
            root (obj): The root node used for verification
            event (obj): The audit event to be verified

        Returns:
            bool: True if membership proof is verified, False otherwise
        """
        if not self.allow_server_roots and root.source != "arweave":
            return False

        # TODO: uncomment when audit created field bug is fixed
        # canon = canonicalize_json(event.event)
        # node_hash_enc = hash_data(canon)
        node_hash_enc = event.hash
        node_hash = decode_hash(node_hash_enc)
        root_hash = decode_hash(root.root_hash)

        proof = decode_membership_proof(event.membership_proof)

        return verify_membership_proof(node_hash, root_hash, proof)

    def can_verify_consistency_proof(self, event: JSONObject) -> bool:
        """
        Can verify consistency proof

        If a given event's consistency across time can be proven.

        Read more at: [Cryptographic Signatures](https://docs.dev.pangea.cloud/docs/audit/tamperproof/tamperproof-audit-logs#cryptographic-signatures)

        Args:
            event (obj): The audit event to be verified.

        Returns:
            bool: True if the consistency can be verifed, False otherwise
        """
        leaf_index = event.get("leaf_index")

        return leaf_index is not None and leaf_index > 0

    def verify_consistency_proof(self, pub_roots: t.Dict[int, t.Optional[JSONObject]], event: JSONObject) -> bool:
        """
        Verify consistency proof

        Checks the cryptographic consistency of the event across time.

        Read more at: [Cryptographic Signatures](https://docs.dev.pangea.cloud/docs/audit/tamperproof/tamperproof-audit-logs#cryptographic-signatures)

        Args:
            pub_roots (dict): list of published root hashes across time
            event (obj): Audit event to be verified.

        Returns:
            bool: True if consistency proof is verified, False otherwise.
        """
        leaf_index = event["leaf_index"]
        curr_root = pub_roots.get(leaf_index + 1)
        prev_root = pub_roots.get(leaf_index)

        if not curr_root or not prev_root:
            return False

        if not self.allow_server_roots and (curr_root.source != "arweave" or prev_root.source != "arweave"):
            return False

        curr_root_hash = decode_hash(curr_root.root_hash)
        prev_root_hash = decode_hash(prev_root.root_hash)
        proof = decode_consistency_proof(curr_root.consistency_proof)

        return verify_consistency_proof(curr_root_hash, prev_root_hash, proof)

    def verify_signature(self, audit_envelope: JSONObject) -> bool:
        """
        Verify signature

        Args:
            audit_envelope (obj):

        Returns:
          bool:
        """
        sign_envelope = self.create_signed_envelope(audit_envelope.envelope.event)
        public_key_b64 = audit_envelope.envelope.public_key
        public_key_bytes = b64decode(public_key_b64)
        return self.sign.verifyMessage(audit_envelope.envelope.signature, sign_envelope, public_key_bytes)

    def root(self, tree_size: int = 0) -> PangeaResponse:
        """
        Retrieve tamperproof verification

        Returns current root hash and consistency proof.

        Args:
            tree_size (int): The size of the tree (the number of records)

        Returns:
            An PangeaResponse.

        Examples:
            response = audit.root(tree_size=7)
        """
        endpoint_name = "root"

        data = {}

        if tree_size > 0:
            data["tree_size"] = tree_size

        return self.request.post(endpoint_name, data=data)

    def create_signed_envelope(self, event: dict) -> dict:
        return {key: val for key, val in event.items() if val is not None}

    def get_buffer_data(self):
        if not self.buffer_data:
            if os.path.exists(self.root_id_filename):
                try:
                    with open(self.root_id_filename, "r") as file:
                        self.buffer_data = file.read()
                except Exception:
                    raise Exception("Error: Failed loading data file from local disk.")

        return self.buffer_data

    def set_buffer_data(self, last_root_enc: str, pending_roots: List[str]):
        buffer_dict = dict()
        buffer_dict["last_root"] = last_root_enc
        buffer_dict["pending_roots"] = pending_roots

        try:
            with open(self.root_id_filename, "w") as file:
                self.buffer_data = json.dumps(buffer_dict)
                file.write(self.buffer_data)
        except Exception:
            raise Exception("Error: Failed saving data file to local disk.")

        return

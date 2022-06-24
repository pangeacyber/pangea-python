# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import typing as t
import json

from pangea.response import JSONObject, PangeaResponse
from .base import ServiceBase

from .audit_util import (
    canonicalize_log,
    decode_hash,
    decode_membership_proof,
    decode_consistency_proof,
    get_arweave_published_roots,
    hash_data,
    verify_consistency_proof,
    verify_membership_proof,
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


class AuditSearchResponse(object):
    """
    Wrap the base Response object to include search pagination support
    """

    def __init__(self, response, data):
        self.response = response
        self.data = data

    def __getattr__(self, attr):
        return getattr(self.response, attr)

    def next(self) -> t.Optional[t.Dict[str, t.Any]]:
        if self.count < self.total:
            return self.data | {"last": self.response.result.last}
        else:
            return None

    @property
    def total(self) -> int:
        if self.success:
            last = self.result["last"]
            total = last.split("|")[1]  # TODO: update once `last` returns an object
            return int(total)
        else:
            return 0

    @property
    def count(self) -> int:
        if self.success:
            last = self.result["last"]
            count = last.split("|")[0]  # TODO: update once `last` returns an object
            return int(count)
        else:
            return 0


class Audit(ServiceBase):
    response_class = AuditSearchResponse
    service_name = "audit"
    version = "v1"
    # In case of Arweave failure, ask the server for the roots
    allow_server_roots = True

    def log(self, input: dict, verify: bool = False) -> PangeaResponse:
        """
        Filter input on valid search params, at least one valid param is required
        """
        endpoint_name = "log"

        data: dict[str, t.Any] = {"event": {}, "return_hash": True}

        for name in SupportedFields:
            if name in input:
                data["event"][name] = input[name]

        for name in SupportedJSONFields:
            if name in input:
                data["event"][name] = json.dumps(input[name])

        if "message" not in data["event"]:
            raise Exception(f"Error: missing required field, no `message` provided")

        resp = self.request.post(endpoint_name, data=data)
        return resp

    def search(
        self,
        query: str = "",
        sources: list = [],
        page_size: int = 20,
        start: str = "",
        end: str = "",
        last: str = "",
        verify: bool = False,
    ) -> AuditSearchResponse:
        """
        The `page_size` param determines the maximum results returned, it must be a positive integer.
        """
        endpoint_name = "search"

        params = {
            "query": query,
            "sources": sources,
            "page_size": page_size,
            "start": start,
            "end": end,
            "last": last,
            "verify": verify,
        }

        if not (isinstance(page_size, int) and page_size > 0):
            raise Exception("The 'page_size' argument must be a positive integer > 0")

        data = {
            "query": query,
            "include_membership_proof": True,
            "include_hash": True,
            "include_root": True,
            "page_size": page_size,
        }

        if start:
            data["start"] = start

        if end:
            data["end"] = end

        if last:
            data["last"] = last

        if sources:
            data["sources"] = sources

        response = self.request.post(endpoint_name, data=data)
        if not response.success:
            return AuditSearchResponse(response, data)

        root = response.result.root

        # if there is no root, we don't have any record migrated to cold. We cannot verify any proof
        if not root:
            response.result.root = {}
            response.result.published_roots = {}
            return AuditSearchResponse(response, data)

        if verify == True:
            for audit in response.result.events:
                # verify membership proofs
                if not self.verify_membership_proof(response.result.root, audit):
                    raise Exception(f"Error: Membership proof failed.")

                # verify consistency proofs
                if not self.verify_consistency_proof(response.result.root, audit):
                    raise Exception(f"Error: Consistency proof failed.")

        response_wrapper = AuditSearchResponse(response, params)
        return response_wrapper

    def search_next(self, response: AuditSearchResponse):
        params = response.next()
        if not params:
            return None
        else:
            return self.search(**params)

    def update_published_roots(
        self, pub_roots: dict[int, t.Optional[JSONObject]], result: JSONObject
    ):
        tree_sizes = set()
        for audit in result.events:
            leaf_index = audit.get("leaf_index")
            if leaf_index is not None:
                tree_sizes.add(leaf_index + 1)
                if leaf_index > 0:
                    tree_sizes.add(leaf_index)
        tree_sizes.add(result.root.size)

        tree_sizes.difference_update(pub_roots.keys())
        if tree_sizes:
            arweave_roots = get_arweave_published_roots(
                result.root.tree_name, list(tree_sizes) + [result.root.size]
            )
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
                    pub_root = resp.result
                    pub_root.source = "pangea"
            pub_roots[tree_size] = pub_root

    def can_verify_membership_proof(self, event: JSONObject) -> bool:
        return event.get("membership_proof") is not None

    def verify_membership_proof(self, root: JSONObject, event: JSONObject) -> bool:
        if not self.allow_server_roots and root.source != "arweave":
            return False

        # TODO: uncomment when audit created field bug is fixed
        # canon = canonicalize_log(event.event)
        # node_hash_enc = hash_data(canon)
        node_hash_enc = event.hash
        node_hash = decode_hash(node_hash_enc)
        root_hash = decode_hash(root.root_hash)
        proof = decode_membership_proof(event.membership_proof)
        return verify_membership_proof(node_hash, root_hash, proof)

    def can_verify_consistency_proof(self, event: JSONObject) -> bool:
        leaf_index = event.get("leaf_index")
        return leaf_index is not None and leaf_index > 0

    def verify_consistency_proof(
        self, pub_roots: dict[int, t.Optional[JSONObject]], event: JSONObject
    ) -> bool:
        leaf_index = event["leaf_index"]
        curr_root = pub_roots.get(leaf_index + 1)
        prev_root = pub_roots.get(leaf_index)

        if not curr_root or not prev_root:
            return False

        if not self.allow_server_roots and (
            curr_root.source != "arweave" or prev_root.source != "arweave"
        ):
            return False

        curr_root_hash = decode_hash(curr_root.root_hash)
        prev_root_hash = decode_hash(prev_root.root_hash)
        proof = decode_consistency_proof(curr_root.consistency_proof)
        return verify_consistency_proof(curr_root_hash, prev_root_hash, proof)

    def root(self, tree_size: int = 0) -> AuditSearchResponse:
        endpoint_name = "root"

        data = {}

        if tree_size > 0:
            data["tree_size"] = tree_size

        response = self.request.post(endpoint_name, data=data)
        return AuditSearchResponse(response, data)

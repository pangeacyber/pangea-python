# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import typing as t
from base64 import b64decode, b64encode
from datetime import date
import json
import requests
from dateutil import parser

from pangea.response import JSONObject, PangeaResponse
from .base import ServiceBase

from .audit_util import (
    base64url_decode,
    bytes_to_json,
    canonicalize_log,
    decode_hash,
    decode_proof,
    decode_root,
    decode_server_response,
    get_arweave_published_roots,
    hash_data,
    to_msg,
    verify_consistency_proof,
    verify_log_proof,
    verify_published_root,
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
            params = {
                "query": self.data["query"],
                "last": self.result["last"],
                "size": self.data["page_size"],
            }

            if hasattr(self.data, "start"):
                params.update({"start": self.data["start"]})

            if hasattr(self.data, "end"):
                params.update({"end": self.data["end"]})

            return params
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

    def log(self, data: dict, verify: bool = False) -> PangeaResponse:
        """
        Filter input on valid search params, at least one valid param is required
        """
        endpoint_name = "log"

        data = {"event": {}, "return_hash": "true"}

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
        size: int = 20,
        start: str = "",
        end: str = "",
        last: str = "",
        verify: bool = False,
    ) -> AuditSearchResponse:
        """
        The `size` param determines the maximum results returned, it must be a positive integer.
        """
        endpoint_name = "search"

        if not (isinstance(size, int) and size > 0):
            raise Exception("The 'size' argument must be a positive integer > 0")

        data = {
            "query": query,
            "include_membership_proof": True,
            "include_hash": True,
            "include_root": True,
        }

        if start:
            data.update({"start": start})

        if end:
            data.update({"end": end})

        if last:
            data.update({"last": last})

        if sources:
            data.update({"sources": sources})

        response = self.request.post(endpoint_name, data=data)

        if response is None:
            raise Exception(f"Error: Empty result from server.")
        elif response.result is None:
            raise Exception(f"Error: Empty result from server.")

        root = response.result.root

        # if there is no root, we don't have any record migrated to cold. We cannot verify any proof
        if not root:
            response.result.root = {}
            response.result.published_roots = {}
            return AuditSearchResponse(response, data)

        # get the size of all the roots needed for the consistency_proofs
        tree_sizes = set()
        for audit in response.result.events:
            leaf_index = audit.get("leaf_index")
            if leaf_index is not None:
                tree_sizes.add(leaf_index)
                if leaf_index > 1:
                    tree_sizes.add(leaf_index - 1)
        tree_sizes.add(root.size)

        # get all the roots from arweave
        response.result.published_roots = {
            tree_size: JSONObject(obj.get("event", {}))
            for tree_size, obj in get_arweave_published_roots(
                root.tree_name, list(tree_sizes) + [root.size]
            ).items()
        }
        for tree_size, root in response.result.published_roots.items():
            root["source"] = "arweave"

        # fill the missing roots from the server
        for tree_size in tree_sizes:
            if tree_size not in response.result.published_roots:
                try:
                    response.result.published_roots[tree_size] = self.root(
                        tree_size
                    ).result.event
                    response.result.published_roots[tree_size]["source"] = "pangea"
                except:
                    pass

        # if we've got the current root from arweave, replace the one from the server
        pub_root = response.result.published_roots.get(root.size)
        if pub_root:
            response.result.root = pub_root

        # calculate the hashes from the event
        for audit in response.result.events:
            canon = canonicalize_log(audit.event)
            audit["calculated_hash"] = hash_data(canon)

        if verify == True:
            for audit in response.result.events:
                # verify membership proofs
                if not self.verify_membership_proof(
                    response.result.root, audit, verify
                ):
                    raise Exception(f"Error: Membership proof failed.")

                # verify consistency proofs
                if not self.verify_consistency_proof(
                    response.result.root, audit, verify
                ):
                    raise Exception(f"Error: Consistency proof failed.")

        response_wrapper = AuditSearchResponse(response, data)
        return response_wrapper

    def verify_membership_proof(
        self, root: JSONObject, audit: JSONObject, required: bool = False
    ) -> bool:
        if not audit.get("membership_proof"):
            return not required

        if not self.allow_server_roots and root.source != "arweave":
            return False

        node_hash = decode_hash(audit.calculated_hash)
        root_hash = decode_hash(root.root_hash)
        proof = decode_proof(audit.membership_proof)
        return verify_log_proof(node_hash, root_hash, proof)

    def verify_consistency_proof(
        self,
        published_roots: dict[int, JSONObject],
        audit: JSONObject,
        required: bool = False,
    ) -> bool:
        leaf_index = audit.get("leaf_index")
        if not leaf_index:
            return not required

        if leaf_index == 1:
            return not required

        curr_root = published_roots.get(leaf_index)
        prev_root = published_roots.get(leaf_index - 1)

        if not curr_root or not prev_root:
            return False

        if not self.allow_server_roots and (
            curr_root.source != "arweave" or prev_root.source != "arweave"
        ):
            return False

        return verify_consistency_proof(curr_root, prev_root)

    def root(self, tree_size: int = 0) -> AuditSearchResponse:
        endpoint_name = "root"

        data = {}

        if tree_size > 0:
            data["tree_size"] = tree_size

        response = self.request.post(endpoint_name, data=data)
        return AuditSearchResponse(response, data)

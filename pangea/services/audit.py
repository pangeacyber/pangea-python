# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from base64 import b64decode, b64encode
from datetime import date

import requests
from dateutil import parser

from pangea.response import JSONObject, PangeaResponse

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

# The fields in a top-level audit log record.
SupportedFields = ["actor", "action", "created", "message", "new", "old", "status", "target"]


class AuditSearchResponse(object):
    """
    Wrap the base Response object to include search pagination support
    """

    def __init__(self, response, data):
        self.response = response
        self.data = data

    def __getattr__(self, attr):
        return getattr(self.response, attr)

    def next(self):
        reg_count = 0
        if self.count and self.count != "":
            reg_count = int(self.count)

        reg_total = 0
        if self.total and self.total != "":
            reg_total = int(self.total)

        if reg_count < reg_total:
            params = {
                "query": self.data["query"],
                "last": self.result["last"],
                "size": self.data["max_results"],
            }

            if hasattr(self.data, "start"):
                params.update({"start": self.data["start"]})

            if hasattr(self.data, "end"):
                params.update({"end": self.data["end"]})

            return params
        else:
            return None

    @property
    def total(self) -> str:
        total = "0"
        if self.success:
            last = self.result.last
            if last is not None:
                total = last.split("|")[1]
            return total
        else:
            return total

    @property
    def count(self) -> str:
        count = "0"
        if self.success:
            last = self.result.last
            if last is not None:
                count = last.split("|")[0]
            return count
        else:
            return count


class Audit(ServiceBase):
    response_class = AuditSearchResponse
    service_name = "audit"
    version = "v1"
    # In case of Arweave failure, ask the server for the roots
    allow_server_roots = True

    def log(self, input: dict, signature=None, public_key=None, verify: bool = False) -> PangeaResponse:
        endpoint_name = "log"

        """
        Filter input on valid search params, at least one valid param is required
        """

        data = {"data": {}, "return_hash": "true"}

        for name in SupportedFields:
            if name in input:
                data["data"][name] = input[name]

        if len(data) < 1:
            raise Exception(f"Error: no valid parameters, require on or more of: {', '.join(SupportedFields)}")

        if "action" not in data["data"]:
            raise Exception(f"Error: missing required field, no `action` provided")

        if "actor" not in data["data"]:
            raise Exception(f"Error: missing required field, no `actor` provided")

        if "message" not in data["data"]:
            raise Exception(f"Error: missing required field, no `message` provided")

        if "status" not in data["data"]:
            raise Exception(f"Error: missing required field, no `status` provided")

        if "new" not in data["data"]:
            raise Exception(f"Error: missing required field, no `new` provided")

        if "old" not in data["data"]:
            raise Exception(f"Error: missing required field, no `old` provided")

        if "target" not in data["data"]:
            raise Exception(f"Error: missing required field, no `target` provided")

        resp = self.request.post(endpoint_name, data=data)

        return resp

    def search(
        self,
        query,
        size: int = 20,
        start: str = "",
        end: str = "",
        last: str = "",
        signature=None,
        public_key=None,
        verify: bool = False,
    ) -> AuditSearchResponse:
        endpoint_name = "search"

        """
        The `size` param determines the maximum results returned, it must be a positive integer.
        """
        if not (isinstance(size, int) and size > 0):
            raise Exception("The 'size' argument must be a positive integer > 0")

        if not query:
            raise Exception(f"Error: Query field is mandatory.")

        data = {
            "query": query,
            "max_results": size,
            "include_membership_proof": True,
            "include_hash": True,
            "include_root": True,
        }

        if start:
            parser.isoparse(start)
            data.update({"start": start})

        if end:
            parser.isoparse(end)
            data.update({"end": end})

        if last:
            data.update({"last": last})

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
        for audit in response.result.audits:
            leaf_index = audit.get("leaf_index")
            if leaf_index is not None:
                tree_sizes.add(leaf_index)
                if leaf_index > 1:
                    tree_sizes.add(leaf_index - 1)
        tree_sizes.add(root.size)

        # get all the roots from arweave
        response.result.published_roots = {
            tree_size: JSONObject(obj.get("data", {}))
            for tree_size, obj in get_arweave_published_roots(root.tree_name, list(tree_sizes) + [root.size]).items()
        }
        for tree_size, root in response.result.published_roots.items():
            root["source"] = "arweave"

        # fill the missing roots from the server
        for tree_size in tree_sizes:
            if tree_size not in response.result.published_roots:
                try:
                    response.result.published_roots[tree_size] = self.root(tree_size).result.data
                    response.result.published_roots[tree_size]["source"] = "pangea"
                except:
                    pass

        # if we've got the current root from arweave, replace the one from the server
        pub_root = response.result.published_roots.get(root.size)
        if pub_root:
            response.result.root = pub_root

        # calculate the hashes from the data
        for audit in response.result.audits:
            canon = canonicalize_log(audit.data)
            audit["calculated_hash"] = hash_data(canon)

        if verify == True:
            for audit in response.result.audits:
                # verify membership proofs
                if not self.verify_membership_proof(response.result.root, audit, verify):
                    raise Exception(f"Error: Membership proof failed.")

                # verify consistency proofs
                if not self.verify_consistency_proof(response.result.root, audit, verify):
                    raise Exception(f"Error: Consistency proof failed.")

        response_wrapper = AuditSearchResponse(response, data)
        return response_wrapper

    def verify_membership_proof(self, root: JSONObject, audit: JSONObject, required: bool = False) -> bool:
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

        if not self.allow_server_roots and (curr_root.source != "arweave" or prev_root.source != "arweave"):
            return False

        return verify_consistency_proof(curr_root, prev_root)

    def root(self, tree_size: int = 0) -> AuditSearchResponse:
        endpoint_name = "root"

        data = {}

        if tree_size > 0:
            data["tree_size"] = tree_size

        response = self.request.post(endpoint_name, data=data)
        return AuditSearchResponse(response, data)

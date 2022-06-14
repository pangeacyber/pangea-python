# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from datetime import date
import requests

from base64 import b64encode, b64decode
from dateutil import parser

from pangea.response import PangeaResponse
from pangea.response import JSONObject
from .base import ServiceBase
from .audit_util import (
    canonicalize_log,
    decode_hash,
    decode_proof,
    decode_root,
    hash_data,
    verify_log_proof,
    to_msg,
    verify_published_root,
    base64url_decode,
    decode_server_response,
    bytes_to_json,
    verify_consistency_proof,
    get_arweave_published_roots    
)

# The fields in a top-level audit log record.
SupportedFields = [
    "actor",
    "action",
    "created",
    "message",
    "new",
    "old",
    "status",
    "target"
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

    def next(self):
        reg_count = 0
        if self.count:
            reg_count = int(self.count)

        reg_total = 0
        if self.total:
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
    allow_server_roots = (
        True  # In case of Arweave failure, ask the server for the roots
    )

    def log(self, input: dict, signature = None, public_key = None, verify: bool = False) -> PangeaResponse:
        endpoint_name = "log"

        """
        Filter input on valid search params, at least one valid param is required
        """

        data = {
	        "data": {},
	        "return_hash": "true"
        }

        for name in SupportedFields:
            if name in input:
                data["data"][name] = input[name]

        if len(data) < 1:
            raise Exception(
                f"Error: no valid parameters, require on or more of: {', '.join(SupportedFields)}"
            )

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
        query: str = "",
        size: int = 20,
        start: str = "",
        end: str = "",
        last: str = "",
        signature = None,
        public_key =  None,
        verify_proofs: bool = False,
    ) -> AuditSearchResponse:
        endpoint_name = "search"

        """
        The `size` param determines the maximum results returned, it must be a positive integer.
        """
        if not (isinstance(size, int) and size > 0):
            raise Exception("The 'size' argument must be a positive integer > 0")

        if not query or not query.strip():
            raise Exception(
                f"Error: Query field is mandatory."
            )

        include_membership_proof = True
        include_hash = True
        include_root = True

        data = {
            "query": query, 
            "max_results": size,
	        "include_membership_proof": include_membership_proof,
            "include_hash": include_hash,
	        "include_root": include_root            
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
            raise Exception(
                f"Error: Empty result from server."
            )
        elif response.result is None:
            raise Exception(
                f"Error: Empty result from server."
            )

        response_result = response.result

        root = response_result.get("root")
        if include_root and not root:
            raise Exception(
                f"Error: `root` field not present."
            )    

        root_hash_coded = root.get("root_hash")
        if include_membership_proof and not root_hash_coded:
            raise Exception(
                f"Error: `root_hash` field not present."
            )    

        audits = response_result.get("audits")
        if not audits:
            raise Exception(
                f"Error: `audits` field not present."
            )        

        tree_sizes = set()
        for a in audits:
            leaf_index = a.get("leaf_index")
            if leaf_index is not None:
                tree_sizes.add(leaf_index)
                tree_sizes.add(max(1, leaf_index - 1))

        try:
            published_roots = get_arweave_published_roots(
                root["tree_name"], list(tree_sizes)
            )
        except Exception as e:
            published_roots = {tree_size: None for tree_size in tree_sizes}

        if published_roots:
            if published_roots.get("tree_size"):
                if self.allow_server_roots:
                    for tree_size in published_roots:
                        if published_roots[tree_size] is None:
                            published_roots[tree_size] = self.root(tree_size).result

                if root_hash_coded is not None:
                    root_hash = decode_hash(root_hash_coded)
                    for a in response_result.audits:
                        leaf_index = a.get("leaf_index")
                        if leaf_index is not None:
                            a["published_roots"] = {
                                "current": published_roots[leaf_index],
                                "previous": published_roots[leaf_index - 1] if leaf_index > 0 else None,
                            }

        if not root.get("tree_name") or not root.get("size"):
            publish_resp_full = get_arweave_published_roots(root["tree_name"], [root["size"]])
            if publish_resp_full is not None:
                publish_resp = publish_resp_full[root["size"]]
            else:
                publish_resp = None
        else:
            publish_resp = None
                
        if publish_resp is not None:
            publish_root_hash = decode_hash(publish_resp.get("root_hash", ""))
            publish_verify = verify_published_root(root_hash, publish_root_hash)

            if not publish_verify:
                raise Exception(f"Error: Published Root Not Valid.")
        else:
            if not self.allow_server_roots:
                raise Exception(f"Error: Published Root Not Valid.")

        response_wrapper = AuditSearchResponse(response, data)

        return response_wrapper


    def verify_membership_proof(
        self, root: JSONObject, audit: JSONObject, required: bool = False
    ) -> bool:
        if not audit.get("membership_proof"):
            return not required
        node_hash = decode_hash(audit.hash)
        root_hash = decode_hash(root.root_hash)
        proof = decode_proof(audit.membership_proof)
        return verify_log_proof(node_hash, root_hash, proof)


    def verify_consistency_proof(
        self, audit: JSONObject, required: bool = False
    ) -> bool:
        if not audit.get("published_roots"):
            return not required

        if not audit.published_roots.get("current"):
            return False

        if not audit.published_roots.get("previous"):
            if audit.get("leaf_index", 0) <= 1:
                return True
            else:
                return False

        return verify_consistency_proof(
            audit.published_roots.current.data, audit.published_roots.previous.data
        )


    def root(self, tree_size: int = 0) -> AuditSearchResponse:
        endpoint_name = "root"

        data = {}

        if tree_size > 0:
            data["tree_size"] = tree_size

        return self.request.post(endpoint_name, data=data)

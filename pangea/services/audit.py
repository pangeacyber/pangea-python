# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from datetime import date
import sys
import uuid

import json
from base64 import b64encode, b64decode
from dateutil import parser

from pangea.response import PangeaResponse
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
    decode_server_response
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
    "target",
    "return_hash",
    "data"
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
        if self.count:  # TODO: fix, this is the wrong check
            params = {
                "query": self.data["query"],
                "last": self.result.last,
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
        if self.success:
            last = self.result.last
            total = last.split("|")[1]  # TODO: update once `last` returns an object
            return total
        else:
            return 0

    @property
    def count(self) -> str:
        if self.success:
            last = self.result.last
            count = last.split("|")[0]  # TODO: update once `last` returns an object
            return count
        else:
            return 0


class Audit(ServiceBase):
    response_class = AuditSearchResponse
    service_name = "audit"
    service_name = "audit-audit-tamper-proof-improve-admin-script"  #"audit-audit-tamper-proof-casual"    # For Testing Only / Remove this line!
    version = "v1"

    def log(self, input: dict, signature = None, public_key = None, verify: bool = False) -> PangeaResponse:
        endpoint_name = "log"

        """
        Filter input on valid search params, at least one valid param is required
        """
        data = {}

        for name in SupportedFields:
            if name in input:
                data[name] = input[name]

        if len(data) < 1:
            raise Exception(
                f"Error: no valid parameters, require on or more of: {', '.join(SupportedFields)}"
            )

        if "data" not in data:
            raise Exception(f"Error: missing required field, no `data` provided")

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
        # TODO: Verify consistency and membership.

        # TODO: Verify signature if verify parameter equal True (Not for beta).
        if verify == True:
            signature = resp["signature"]

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

        include_membership_proof = verify_proofs
        include_hash = verify_proofs
        include_root = verify_proofs

        data = {
            "query": query, 
            "max_results": size,
	        "include_membership_proof": include_membership_proof,
            "include_hash": include_hash,
	        "include_root": include_root            
            }

        if start:
            if not parser.isoparse(start):
                raise Exception(
                    f"Error: invalid start date."
                )
            data.update({"start": start})

        if end:
            if not parser.isoparse(end):
                raise Exception(
                    f"Error: invalid end date."
                )
            data.update({"end": end})

        if last:
            data.update({"last": last})

        resp = self.request.post(endpoint_name, data=data)

        if resp is None:
            raise Exception(
                f"Error: Empty result from server."
            )
        elif resp.result is None:
            raise Exception(
                f"Error: Empty result from server."
            )

        resp = resp.result

        if include_root == True and resp["root"] is None:
            raise Exception(
                f"Error: Invalid response from server, root field not present."
            )

        if include_membership_proof == True and resp["root"]["root_hash"] is None:
            raise Exception(
                f"Error: Invalid response from server, root_hash field not present in root."
            )

        root = resp["root"]["root_hash"]
        root_verified = False

        if "audits" in resp:
            audits = resp["audits"]

            if root is not None:
                root_hash = decode_root(root).root_hash
                for a in audits:
                    stripped_audit = {k: a[k] for k in SupportedFields if k in a}
                    canon_audit = canonicalize_log(stripped_audit)
                    audit_hash = hash_data(canon_audit)

                    a["verification"] = {
                        "log": to_msg(audit_hash == a["hash"]),
                        "root": to_msg(root_verified),
                    }

                    if "membership_proof" in a:
                        node_hash = decode_hash(a["hash"])
                        proof = decode_proof(a["membership_proof"])
                        if not verify_log_proof(node_hash, root_hash, proof):
                            raise Exception(
                                f"Error: invalid Membership Proof."
                            )

#        proof_url = base64url_decode(resp["root"]["url"])
        proof_url = resp["root"]["url"]
        publish_resp = self.request.get(proof_url, None)

        if publish_resp is None:
            raise Exception(
                f"Error: Empty result from server."
            )
        elif publish_resp.result is None:
            raise Exception(
                f"Error: Empty result from server."
            )

        publish_resp_b64 = publish_resp.result
        publish_resp =  decode_server_response(publish_resp_b64)        

        #  Server Response (Test / Remove this code).
        publish_resp = {
            "data": {
	        "published_at": "2022-06-06T17:40:29.049Z",
	        "size": 32,
	        "root_hash": "693cf43181981a8621da38247055ba2072d5cc8b2d905a3cd531677122cd3955",
	        "consistency_proof": "W3sic2lkZSI6ICJsZWZ0IiwgImhhc2giOiAiNDE3NjI2OTA5NTQ0MzFmOWI4ZTA3MzE4NTE5ZGU5YmIwZWQ4ODFlNzg3OWMwZjY0M2NjNDIyYmI2YTBiM2E0ZSJ9LCB7InNpZGUiOiAicmlnaHQiLCAiaGFzaCI6ICJhNTM4ZWRhNDEzNGIzNzJhZGZkODQ3Yjg0NTNjZmQ4ODVlYmVmY2RmZDdmNzJhZTVhNGI3MDgzMzVhOTE0OGQxIn0sIHsic2lkZSI6ICJsZWZ0IiwgImhhc2giOiAiN2NmZTViZjFmY2Y0NTAyNjIyMTBlMzQ1M2VmN2JiNjNkYmI0OTYzOWE5MzI4OTA3MGEwNzFmNDM3ZDRkYWMxMiJ9LCB7InNpZGUiOiAicmlnaHQiLCAiaGFzaCI6ICI4Mzg2MGYyZjk1MzRhM2VjNjhmODA2YTM2YmViMWE0NjNiNjEwOWQ1NDA4ZjJkODRhYzViYTk4NDgxOTliZDg2In0sIHsic2lkZSI6ICJsZWZ0IiwgImhhc2giOiAiNDk5OTNjZjRjNzliYTBlMTk1ZTMwYzQ1OGM5M2FiYmNmOTk0MDJjNzAyOTU1YWUwZDY0OGY3MTRkM2ViMDRhNyJ9XQ==",
	        "url": "http://arweave.net/tx/AXjOQAJrs3yQeBiEitm7baaoB9D47Aguf5YenRGQl_o/data/",  # "http://arweave.net/tx/AXjOQAJrs3yQeBiEitm7baaoB9D47Aguf5YenRGQl_o/data/"
	        }
        }        
        #  End Server Response (Test / Remove this code).

        publish_root_hash = decode_hash(publish_resp["data"]["root_hash"])
        publish_verify = verify_published_root(root_hash, publish_root_hash)

        if not publish_verify:
            raise Exception(
                f"Error: Published Root Not Valid."
            )

        response_wrapper = AuditSearchResponse(resp, data)

        return response_wrapper

    # TODO: This is a hack, find a better way to handle pagination
    def search_next(self, data: dict = {}):
        query = data.get("query", "")
        del data["query"]

        return self.search(query, **data)    

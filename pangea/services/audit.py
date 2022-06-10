# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from datetime import date
import requests

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
    decode_server_response,
    bytes_to_json
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
        if self.count and self.count != "":
            reg_count = int(self.count)
        if reg_count > 0:
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

        if include_root == True and response_result["root"] is None:
            raise Exception(
                f"Error: Invalid response from server, root field not present."
            )

        if include_membership_proof == True and response_result["root"]["root_hash"] is None:
            raise Exception(
                f"Error: Invalid response from server, root_hash field not present in root."
            )

        root = response_result["root"]["root_hash"]
        audits = response_result["audits"]

        if audits is None:
            raise Exception(
                f"Error: `audits` field not present."
            )        

        if root is not None:
            root_hash = decode_hash(root)
            for a in audits:
                if "membership_proof" in a:
                    node_hash = decode_hash(a["hash"])
                    proof = decode_proof(a["membership_proof"])
                    if not verify_log_proof(node_hash, root_hash, proof):
                        raise Exception(
                            f"Error: Invalid Membership Proof."
                        )
                elif verify_proofs:
                    raise Exception(
                        f"Error: Membership Proofs not present in Audits."
                    )


        root_url = response_result["root"]["url"]
        if root_url is None:
            raise Exception(
                f"Error: `url` field not present in root field."
            )        

        publish_resp = requests.get(root_url)

        if publish_resp is None:
            raise Exception(
                f"Error: Empty result from server."
            )
        elif publish_resp.text is None:
            raise Exception(
                f"Error: Empty result from server."
                )

        publish_resp_b64 = publish_resp.text
        publish_resp = bytes_to_json(base64url_decode(publish_resp_b64))

        publish_root_hash = decode_hash(publish_resp["root_hash"])
        publish_verify = verify_published_root(root_hash, publish_root_hash)

        if not publish_verify:
            raise Exception(
                f"Error: Published Root Not Valid."
            )

        response_wrapper = AuditSearchResponse(response, data)

        return response_wrapper

    # TODO: This is a hack, find a better way to handle pagination
    def search_next(self, data: dict = {}):
        query = data.get("query", "")
        del data["query"]

        return self.search(query, **data)    

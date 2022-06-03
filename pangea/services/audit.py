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
    version = "v1"

    def log(self, input: dict) -> PangeaResponse:
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

        if "message" not in data:
            raise Exception(f"Error: missing required field, no `message` provided")


        response = self.request.post(endpoint_name, data=data)
        # TODO: Verify consistency and membership.

        return response


    def search(
        self,
        query: str = "",
        size: int = 20,
        start: str = "",
        end: str = "",
        last: str = "",
        signature = None,
        public_key =  None,
        verify: bool = False,
    ) -> AuditSearchResponse:
        endpoint_name = "search"
        
        """
        The `size` param determines the maximum results returned, it must be a positive integer.
        """
        if not (isinstance(size, int) and size > 0):
            raise Exception("The 'size' argument must be a positive integer > 0")

        data = {"query": query, "max_results": size}

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

##  Test Server Response
        resp = {
    "request_id": "placeholder",
    "request_time": "2022-06-02T16:39:07.450Z",
    "response_time": "2022-06-02T16:39:07.450Z",
    "status_code": 200,
    "status": "success",
    "result": {
        "root": {
            "hash": "030000009727d718a6cf4f986dd2bb467c3cdfc265929449173e89048b8926908de4c39d"
        },
        "audits": [
            {
                "actor": "testing1",
                "message": "zzz",
                "created": "2022-06-02T16:35:25.973960+00:00",
                "proof": "W3sic2lkZSI6ICJsZWZ0IiwgImhhc2giOiAiZDYzYjJhMDQwYmEyMWVmNjk3YTA2MDM5YzI3MGQ4NzgwN2YzNjUyZGMzZDAwMDZmZDUzNzM0M2E0NmNhNjkyYyJ9LCB7InNpZGUiOiAibGVmdCIsICJoYXNoIjogIjdlZDFlYTJjMzEzYzFjYWNiODFhZGUwYjNjY2M0MmYyMDkwMjNjYjdmZDlkNjVlN2Q3NmNlYTFjNWNjNWQxN2MifV0=",
                "hash": "6fe11c634524c9c0c48b77a73fdf8799c744af9c7f9bf5f4f78c4ece24ed6c6d"
            },
            {
                "actor": "testing1",
                "message": "zzz",
                "created": "2022-06-02T16:35:25.003627+00:00",
                "proof": "W3sic2lkZSI6ICJsZWZ0IiwgImhhc2giOiAiOTI2ODk3OGEwYTM2OTIzMmYwZmEzOTFhODRhMmI5NjhkNWViN2YwYzJlZTYzYzEzZjk1YmUyYzRiNjhjOWM3YiJ9LCB7InNpZGUiOiAicmlnaHQiLCAiaGFzaCI6ICI2ZmUxMWM2MzQ1MjRjOWMwYzQ4Yjc3YTczZmRmODc5OWM3NDRhZjljN2Y5YmY1ZjRmNzhjNGVjZTI0ZWQ2YzZkIn0sIHsic2lkZSI6ICJsZWZ0IiwgImhhc2giOiAiN2VkMWVhMmMzMTNjMWNhY2I4MWFkZTBiM2NjYzQyZjIwOTAyM2NiN2ZkOWQ2NWU3ZDc2Y2VhMWM1Y2M1ZDE3YyJ9XQ==",
                "hash": "b5b7f80e55111e7fc7c4c7be0fd3ecc7a11b8f1ed0bfef80ea5a3cf66d1fb708"
            },
            {
                "actor": "testing1",
                "message": "zzz",
                "created": "2022-06-02T16:35:23.117489+00:00",
                "proof": "W3sic2lkZSI6ICJyaWdodCIsICJoYXNoIjogImI1YjdmODBlNTUxMTFlN2ZjN2M0YzdiZTBmZDNlY2M3YTExYjhmMWVkMGJmZWY4MGVhNWEzY2Y2NmQxZmI3MDgifSwgeyJzaWRlIjogInJpZ2h0IiwgImhhc2giOiAiNmZlMTFjNjM0NTI0YzljMGM0OGI3N2E3M2ZkZjg3OTljNzQ0YWY5YzdmOWJmNWY0Zjc4YzRlY2UyNGVkNmM2ZCJ9LCB7InNpZGUiOiAibGVmdCIsICJoYXNoIjogIjdlZDFlYTJjMzEzYzFjYWNiODFhZGUwYjNjY2M0MmYyMDkwMjNjYjdmZDlkNjVlN2Q3NmNlYTFjNWNjNWQxN2MifV0=",
                "hash": "9268978a0a369232f0fa391a84a2b968d5eb7f0c2ee63c13f95be2c4b68c9c7b"
            }
        ],
        "last": "3|3|"
    },
    "summary": "success"
}
    
        root = resp["result"]["root"]["hash"]
        root_verified = False

        if "result" in resp and "audits" in resp["result"]:
            audits = resp["result"]["audits"]

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

                    if "proof" in a:
                        node_hash = decode_hash(a["hash"])
                        proof = decode_proof(a["proof"])
                        if verify_log_proof(node_hash, root_hash, proof):
                            print("Verified!")
                            root_verified = True
                            if not root_verified:
                                raise Exception(
                                    f"Error: invalid Root Proof."
                                )

                        a["verification"]["proof"] = to_msg(verify_log_proof(node_hash, root_hash, proof))  

        # TODO: Verify against published root.

        response_wrapper = AuditSearchResponse(response, data)

        return response_wrapper

    # TODO: This is a hack, find a better way to handle pagination
    def search_next(self, data: dict = {}):
        query = data.get("query", "")
        del data["query"]

        return self.search(query, **data)    

# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import base64
import json
import struct
import requests
from binascii import hexlify, unhexlify
from dataclasses import dataclass
from hashlib import sha256
from dateutil import parser
from typing import Optional

Hash = bytes

JSON_TYPES = [int, float, str, bool]

ARWEAVE_BASE_URL = "https://arweave.net"

@dataclass
class HotRoot:
    tree_size: int
    root_hash: Hash
    tree_id: str


@dataclass
class Root:
    tree_size: int
    root_hash: Hash


@dataclass
class ProofItem:
    side: str
    node_hash: Hash


Proof = list[ProofItem]


@dataclass
class RootProofItem:
    node_hash: Hash
    proof: Proof


RootProof = list[RootProofItem]


def decode_hash(hexhash: str) -> Hash:
    return unhexlify(hexhash.encode("utf8"))


def encode_hash(hash_: Hash) -> str:
    return hexlify(hash_).decode("utf8")


def hash_pair(hash1: Hash, hash2: Hash) -> Hash:
    return sha256(hash1 + hash2).digest()


def decode_root(data: str) -> Root:
    tree_size_enc = unhexlify(data[:8].encode("utf8"))
    data = data[8:]
    tree_size = struct.unpack("=L", tree_size_enc)[0]

    root_hash = decode_hash(data[: 32 * 2])
    data = data[32 * 2 :]

    return Root(tree_size=tree_size, root_hash=root_hash)


def decode_proof(data: str) -> Proof:
    proof: Proof = []
    for item in data.split(","):
        parts = item.split(":")
        proof.append(ProofItem(side="left" if parts[0] == "l" else "right", node_hash=decode_hash(parts[1])))
    return proof


def decode_root_proof(data: list[str]) -> RootProof:
    root_proof = []
    for item in data:
        ndx = item.index(",")
        root_proof.append(
            RootProofItem(node_hash=decode_hash(item[:ndx].split(":")[1]), proof=decode_proof(item[ndx + 1 :]))
        )
    return root_proof


def decode_server_response(data: str) -> dict:
    data_dec = base64.b64decode(data.encode("utf8"))
    data_obj = json.loads(data_dec)
    return data_obj


def verify_log_proof(node_hash: Hash, root_hash: Hash, proof: Proof) -> bool:
    for proof_item in proof:
        proof_hash = proof_item.node_hash
        node_hash = hash_pair(proof_hash, node_hash) if proof_item.side == "left" else hash_pair(node_hash, proof_hash)
    return root_hash == node_hash


def verify_published_root(root_hash: Hash, publish_hash: Hash) -> bool:
    return root_hash == publish_hash


def canonicalize_log(audit: dict) -> bytes:
    def _default(obj):
        if not any(isinstance(obj, typ) for typ in JSON_TYPES):
            return str(obj)
        else:
            return obj

    # stringify invalid JSON types before canonicalizing
    return json.dumps(
        audit, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True, default=_default
    ).encode("utf-8")


def hash_data(data: bytes) -> str:
    return sha256(data).hexdigest()


def to_msg(b):
    return "OK" if b else "FAILED"   


def base64url_decode(input):
    """Helper method to base64url_decode a string.

    Args:
        input (str): A base64url_encoded string to decode.

    """
    rem = len(input) % 4

    if rem > 0:
        input += "=" * (4 - rem)

    return base64.urlsafe_b64decode(input)


def bytes_to_json(input: bytes) -> dict:
    return json.loads(input.decode("utf8"))


def arweave_transaction_url(trans_id: str):
    return f"{ARWEAVE_BASE_URL}/tx/{trans_id}/data/"


def arweave_graphql_url():
    return f"{ARWEAVE_BASE_URL}/graphql"


def get_arweave_published_roots(
    tree_name: str, tree_sizes: list[int]
) -> dict[int, Optional[dict]]:
    if len(tree_sizes) == 0:
        return {}

    query = """
    {
        transactions(
  			tags: [
                {
                    name: "tree_size"
                    values: [{tree_sizes}]
                },
                {
                    name: "tree_name"
                    values: ["{tree_name}"]
                }
    	    ]      
        ) {
            edges {
                node {
                    id
                    tags {
                        name
                        value
                    }
                }
            }
        }
    }
    """.replace(
        "{tree_sizes}", ", ".join(f'"{tree_size}"' for tree_size in tree_sizes)
    ).replace(
        "{tree_name}", tree_name
    )

    resp = requests.post(arweave_graphql_url(), json={"query": query})
    resp.raise_for_status()
    ans: dict[int, Optional[dict]] = {tree_size: None for tree_size in tree_sizes}
    data = resp.json()

    if data["data"]["transactions"].get("edges"):
        for edge in data["data"]["transactions"]["edges"]:
            node_id = edge["node"]["id"]
            tree_size = int(
                next(
                    tag["value"]
                    for tag in edge["node"]["tags"]
                    if tag["name"] == "tree_size"
                )
            )
            url = arweave_transaction_url(node_id)

            # TODO: do all the requests concurrently
            resp2 = requests.get(url)
            if resp2.status_code == 200 and resp2.text.strip() != "": 
                ans[tree_size] = json.loads(base64url_decode(resp2.text))
                return ans
    return {}


def verify_consistency_proof(new_root: dict, prev_root: dict) -> bool:
    if new_root is None or prev_root is None:
        return False
    prev_root_hash = decode_hash(prev_root["root_hash"])
    new_root_hash = decode_hash(new_root["root_hash"])
    consistency_proof = decode_root_proof(new_root["consistency_proof"])

    # check the prev_root
    root_hash = consistency_proof[0].node_hash
    for item in consistency_proof[1:]:
        root_hash = hash_pair(item.node_hash, root_hash)

    if root_hash != prev_root_hash:
        return False

    for i, item in enumerate(consistency_proof):
        if not verify_log_proof(item.node_hash, new_root_hash, item.proof):
            print(f"failed validation proof number {i}")
            return False

    return True

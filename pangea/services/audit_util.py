# Copyright 2021 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import base64
import json
import struct
from binascii import hexlify, unhexlify
from dataclasses import dataclass
from hashlib import sha256
from dateutil import parser

Hash = bytes


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
    side: str  # TODO: literal "left" or "right"
    node_hash: Hash


Proof = list[ProofItem]

#class AuditError(Exception):
    # TODO: complete
#    pass

#class AuditInvalidParameterError(AuditError):
    # TODO: complete
#    pass


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
    data_dec = base64.b64decode(data.encode("utf8"))
    data_obj = json.loads(data_dec)
    proof = [ProofItem(side=item["side"], node_hash=decode_hash(item["hash"])) for item in data_obj]
    return proof


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


JSON_TYPES = [int, float, str, bool]


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
        input += b"=" * (4 - rem)

    return base64.urlsafe_b64decode(input)

    

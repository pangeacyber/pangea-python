# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import argparse
import io
import math
import os
import sys
import typing as t
from itertools import groupby

import pangea.services.audit.util as audit_util
from pangea.services import Audit
from pangea.services.audit.models import EventEnvelope
from pangea.tools_util import Event, SequenceFollower, exit_with_error, file_events, init_audit, print_progress_bar


class Errors(t.TypedDict):
    hash: int
    membership_proof: int
    missing: int
    not_persisted: int
    wrong_buffer: int
    buffer_missing: int


root_hashes: dict[int, str] = {}


def num_lines(f: io.TextIOWrapper) -> int:
    res = sum(1 for _ in f)
    f.seek(0)
    return res


def path2index(tree_size: int, path: str) -> int:
    """
    Given a tree size (total number of leaves) and a proof, returns
    the associated leaf index.
    """
    ans = 0
    for side in reversed(path):
        size_left = _tree_size_left(tree_size)
        size_right = tree_size - size_left
        if side == "l":
            ans += size_left
            tree_size = size_right
        else:
            tree_size = size_left
    return ans


def index2path(tree_size: int, leaf_index: int) -> str:
    """
    Get the proof sides (l/r sequence) for a given leaf index and tree size
    """
    revpath = []
    while tree_size > 1:
        size_left = _tree_size_left(tree_size)
        size_right = tree_size - size_left
        if leaf_index < size_left:
            revpath.append("r")
            tree_size = size_left
        else:
            revpath.append("l")
            tree_size = size_right
            leaf_index -= size_left
    return "".join(reversed(revpath))


def get_path_size(tree_size: int, leaf_index: int) -> int:
    """
    Return the size of the path for a given tree_size and leaf_number
    """
    return len(index2path(tree_size, leaf_index))


def _tree_size_left(tree_size: int) -> int:
    """if the tree has size tree_size, return the size of the left child"""
    if tree_size <= 1:
        return tree_size
    return 2 ** (math.ceil(math.log2(tree_size)) - 1)


def get_proof_path(proof: str) -> str:
    return "".join(elem[0] for elem in proof.split(","))


def height(size: int) -> int:
    return int(math.log2(size)) + 1


def index_number(tree_height: int, membership_proof: str) -> int:
    decoded_proof = audit_util.decode_membership_proof(membership_proof)
    idx_number: int = 0
    for idx, proof in enumerate(decoded_proof):
        if proof.side == "left":
            idx_number += round(2 ** (tree_height - idx - 1))
    return idx_number


def verify_hash(data: dict, data_hash: str) -> bool:
    """Verify the hash of an event"""
    succeeded = False
    try:
        if not audit_util.verify_envelope_hash(EventEnvelope(**data), data_hash):
            print("Hash failed: ", data)
            raise ValueError("Hash does not match")
        succeeded = True
    except Exception:
        pass
    return succeeded


def get_tree_size(event: Event):
    # TODO: other formats
    return event["tree_size"]


def verify_membership_proof(node_hash: str, root_hash: str, proof: str) -> bool:
    succeeded = False
    try:
        root_hash_dec = audit_util.decode_hash(root_hash)
        node_hash_dec = audit_util.decode_hash(node_hash)
        proof_dec = audit_util.decode_membership_proof(proof)
        succeeded = audit_util.verify_membership_proof(node_hash_dec, root_hash_dec, proof_dec)
    except Exception:
        pass
    return succeeded


def get_root_hash(audit: Audit, tree_size: int) -> str:
    resp = audit.root(tree_size)
    if not resp.success:
        raise ValueError(f"Error getting root: {resp.status}")
    return resp.result.data.root_hash


def print_error(msg: str, level: str = "error"):
    if level == "warning":
        dot = "🟡"
    else:
        dot = "🔴"
    print(f"{dot} {msg:200s}")


def deep_verify(audit: Audit, file: io.TextIOWrapper) -> Errors:
    print("Counting events...", end="\r")
    total_events = num_lines(file)
    print(f"Counting events... {total_events}")

    cnt = 1

    errors: Errors = {
        "hash": 0,
        "membership_proof": 0,
        "buffer_missing": 0,
        "missing": 0,
        "not_persisted": 0,
        "wrong_buffer": 0,
    }

    events = file_events(root_hashes, file)
    events_by_idx: list[Event] | t.Iterator[Event]
    cold_indexes = SequenceFollower()
    for leaf_index, events_by_idx in groupby(events, lambda event: event.get("leaf_index")):
        events_by_idx = list(events_by_idx)
        buffer_lines = (cnt, cnt + len(events_by_idx) - 1)
        if leaf_index is None:
            print_error(
                f"Lines {buffer_lines[0]}-{buffer_lines[1]} ({buffer_lines[1]-buffer_lines[0]+1}): Buffer was not persisted"
            )
            errors["not_persisted"] += len(events_by_idx)
            cnt += len(events_by_idx)
            continue

        cold_indexes.add(leaf_index)

        cold_path_size: t.Optional[int] = None
        hot_indexes: set[int] = set()
        for i, event in enumerate(events_by_idx):
            cnt += 1
            tree_size = get_tree_size(event)
            if tree_size not in root_hashes:
                root_hashes[tree_size] = get_root_hash(audit, tree_size)
            cold_path_size = cold_path_size or get_path_size(tree_size, leaf_index)

            print_progress_bar(cnt, total_events, "Verifying events...")
            if not verify_hash(event["envelope"], event["hash"]):
                errors["hash"] += 1

            elif not verify_membership_proof(event["hash"], root_hashes[tree_size], event.get("membership_proof")):
                errors["membership_proof"] += 1

            if "membership_proof" not in event:
                # cannot continue without a membership proof
                continue

            path = get_proof_path(event["membership_proof"])
            if cold_path_size == 0:
                hot_path = path
                cold_path = ""
            else:
                hot_path = path[:-cold_path_size]
                cold_path = path[-cold_path_size:]

            cold_idx = path2index(tree_size, cold_path)
            if cold_idx != leaf_index:
                errors["wrong_buffer"] += 1

            hot_idx = path2index(len(events_by_idx), hot_path)
            hot_indexes.add(hot_idx)

        hot_indexes_diff = set(range(len(events_by_idx))) - hot_indexes
        if len(hot_indexes_diff) > 0:
            errors["missing"] += len(hot_indexes_diff)
            print(f"missing hot indexes: {hot_indexes_diff}")
            print(f"hot_indexes: {hot_indexes} ")
            print(f"events:")
            for e in events_by_idx:
                print(e)
            print_error(
                f"Lines {buffer_lines[0]}-{buffer_lines[1]} ({buffer_lines[1]-buffer_lines[0]}), Buffer #{cold_idx}: {len(hot_indexes_diff)} event(s) missing"
            )

    cold_holes = cold_indexes.holes()
    if cold_holes:
        errors["buffer_missing"] += len(cold_holes)
        print_error(f"{len(cold_holes)} buffer(s) missing")

    print_progress_bar(total_events, total_events, "Verifying events...")
    return errors


def create_parser():
    parser = argparse.ArgumentParser(description="Pangea Audit Event Deep Verifier")
    parser.add_argument(
        "--token", "-t", default=os.getenv("PANGEA_TOKEN"), help="Pangea token (default: env PANGEA_TOKEN)"
    )
    parser.add_argument(
        "--domain", "-d", default=os.getenv("PANGEA_DOMAIN"), help="Pangea domain (default: env PANGEA_DOMAIN)"
    )
    parser.add_argument(
        "--file",
        "-f",
        required=True,
        type=argparse.FileType("r"),
        help="Event input file. Must be a collection of " "JSON Objects separated by newlines",
    )
    return parser


def parse_args(parser):
    args = parser.parse_args()

    if not args.token:
        raise ValueError("token missing")

    if not args.domain:
        raise ValueError("domain missing")

    return args


def main():
    parser = create_parser()
    try:
        args = parse_args(parser)
    except Exception as e:
        parser.print_usage()
        exit_with_error(str(e))

    print("Pangea Audit Event Deep Verifier\n")

    try:
        audit = init_audit(args.token, args.domain)
        errors = deep_verify(audit, args.file)

        print("\n\nTotal errors:")
        for key, val in errors.items():
            print(f"\t{key.title()}: {val}")
        print()

    except Exception as e:
        import traceback

        print(traceback.format_exc())
        exit_with_error(str(e))

    print("Done.")
    sys.exit(0)


if __name__ == "__main__":
    main()

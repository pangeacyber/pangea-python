"""
Command-line tool for verifying audits. 

Usage: python verify_audit.py [-f filename] [-vvv]

    -f filename: input file (stdin if no filename is provided)
    -v[vv]: verbose level

You can provide a single event (obtained from the PUC) or the result from a search call.
In the latter case, all the events are verified.
"""

from dataclasses import dataclass
import json
import sys
from typing import Optional
import logging
from pangea.services.audit_util import (
    canonicalize_log,
    hash_data,
    get_arweave_published_roots,
    verify_consistency_proof,
    verify_membership_proof,
    decode_hash,
    decode_membership_proof,
    decode_consistency_proof,
)

logger = logging.Logger("verifier")


verbose_level = 0
pub_roots: dict[int, dict] = {}

GREEN = "🟢"
WHITE = "⚪️"
RED = "🔴"


@dataclass
class Status:
    ok: int
    couldnt: int
    failed: int

    def __iadd__(self, other):
        self.ok += other.ok
        self.couldnt += other.couldnt
        self.failed += other.failed
        return self


def _print_msg(txt: str, succeeded: Optional[bool], error_msg: str = ""):
    if verbose_level < 1:
        return

    logger.log(
        logging.INFO,
        txt,
        extra={"is_result": True, "succeeded": succeeded, "error": error_msg},
    )


def _verify_hash(data: dict, data_hash: str) -> Optional[bool]:
    error_msg = ""
    try:
        data_canon = canonicalize_log(data)
        computed_hash = hash_data(data_canon)
        computed_hash_dec = decode_hash(computed_hash)
        data_hash_dec = decode_hash(data_hash)
        if computed_hash_dec != data_hash_dec:
            raise ValueError("hash does not match")
        succeeded = True
    except Exception as e:
        succeeded = False
        error_msg = str(e)
    _print_msg("Hash", succeeded, error_msg)
    return succeeded


def _verify_membership_proof(
    tree_name: str, tree_size: int, node_hash: str, proof: Optional[str]
) -> Optional[bool]:
    global pub_roots

    if proof is None:
        succeeded = None
        error_msg = "event not published yet"
    else:
        error_msg = ""
        try:
            if tree_size not in pub_roots:
                pub_roots |= {
                    int(k): v
                    for k, v in get_arweave_published_roots(
                        tree_name, [tree_size]
                    ).items()
                }
            if tree_size not in pub_roots:
                raise ValueError("published root could not be retrieved")
            root_hash_dec = decode_hash(pub_roots[tree_size]["root_hash"])
            node_hash_dec = decode_hash(node_hash)
            proof_dec = decode_membership_proof(proof)
            succeeded = verify_membership_proof(node_hash_dec, root_hash_dec, proof_dec)
        except Exception as e:
            succeeded = False
            error_msg = str(e)

    _print_msg("Membership proof", succeeded, error_msg)
    return succeeded


def _verify_consistency_proof(
    tree_name: str, leaf_index: Optional[int]
) -> Optional[bool]:
    global pub_roots

    if leaf_index is None:
        succeeded = None
        error_msg = "event not published yet"

    elif leaf_index == 0:
        succeeded = None
        error_msg = "event published in the first leaf"
    else:
        error_msg = ""
        try:
            pub_roots |= {
                int(k): v
                for k, v in get_arweave_published_roots(
                    tree_name, [leaf_index + 1, leaf_index]
                ).items()
            }
            if leaf_index + 1 not in pub_roots or leaf_index not in pub_roots:
                raise ValueError("published roots could not be retrieved")

            curr_root = pub_roots[leaf_index + 1]
            prev_root = pub_roots[leaf_index]
            curr_root_hash = decode_hash(curr_root["root_hash"])
            prev_root_hash = decode_hash(prev_root["root_hash"])
            proof = decode_consistency_proof(curr_root["consistency_proof"])
            succeeded = verify_consistency_proof(curr_root_hash, prev_root_hash, proof)

        except Exception as e:
            succeeded = False
            error_msg = str(e)
    _print_msg("Consistency proof", succeeded, error_msg)
    return succeeded


def verify_multiple(root: dict, events: list[dict]) -> Status:
    """
    Verify a list of events.
    Returns a status.
    """

    global verbose_level
    verbose_level -= 1

    status = Status(0, 0, 0)

    for event in events:
        status += verify_single(event | {"root": root})

    if verbose_level >= 0:
        if status.failed > 0:
            print(f"{RED} Verification failed: {status.failed} events")
        if status.couldnt > 0:
            print(f"{WHITE} Could not verify: {status.couldnt} events")
        if status.ok > 0:
            print(f"{GREEN} Verification succeeded: {status.ok} events")

    return status


def verify_single(data: dict) -> Status:
    """
    Verify a single event.
    Returns a status.
    """
    ok_hash = _verify_hash(data["event"], data["hash"])
    ok_membership = _verify_membership_proof(
        data["root"]["tree_name"],
        data["root"]["size"],
        data["hash"],
        data.get("membership_proof"),
    )
    ok_consistency = _verify_consistency_proof(
        data["root"]["tree_name"], data["leaf_index"]
    )

    if verbose_level > 0:
        print("")

    all_ok = ok_hash is True and ok_membership is True and ok_consistency is True
    any_failed = ok_hash is False or ok_membership is False or ok_consistency is False
    return Status(
        1 if all_ok else 0,
        1 if not all_ok and not any_failed else 0,
        1 if any_failed else 0,
    )


def print_help():
    print(f"usage: {sys.argv[0]} [--file fname] [-v[vv]]")
    print("")


class VerifierFormatter(logging.Formatter):
    def format(self, record):
        if hasattr(record, "is_result"):
            if record.succeeded:
                point = GREEN
            elif record.succeeded is None:
                point = WHITE
            else:
                point = RED

            error = getattr(record, "error", "")
            if error:
                error = f"({error})"

            return f"{record.msg:20s} {point}  {error}"
        else:
            return record.msg


def main():
    global verbose_level
    handler = logging.StreamHandler()
    handler.setFormatter(VerifierFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    i = 1
    fin = sys.stdin

    if len(sys.argv) < 2:
        print_help()
        sys.exit(1)

    while i < len(sys.argv):
        if sys.argv[i] in ["-f", "--file"]:
            i += 1
            fin = open(sys.argv[i])

        elif sys.argv[i] == "-vvv":
            verbose_level = 3
        elif sys.argv[i] == "-vv":
            verbose_level = 2
        elif sys.argv[i] == "-v":
            verbose_level = 1

        else:
            print_help()
            sys.exit(1)

        i += 1

    data = json.load(fin)
    events = data.get("result", {}).get("events", [])

    logger.info("Pangea Audit - Verification Tool")
    logger.info("")

    status = (
        verify_multiple(data["result"]["root"], events)
        if events
        else verify_single(data)
    )

    logger.info("")
    if not status.couldnt and not status.failed:
        logger.info("✨✨ Verification succeeded ✨✨")
    elif status.failed:
        logger.info("🚩🚩 Verification failed 🚩🚩")
    else:
        logger.info("✨ Verification partially succeeded ✨")
    logger.info("")

    return 0 if not status.couldnt and not status.failed else 1


if __name__ == "__main__":
    main()

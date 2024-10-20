"""
Command-line tool for verifying audits.

Usage: python verify_audit.py [-f filename]

    -f filename: input file (stdin if no filename is provided)

You can provide a single event (obtained from the PUC) or the result from a search call.
In the latter case, all the events are verified.
"""

import argparse
import json
import logging
import os
import sys
from collections.abc import Set
from enum import Enum
from typing import Dict, Iterable, List, Optional, Union

from pangea.config import PangeaConfig
from pangea.exceptions import TreeNotFoundException
from pangea.services import Audit
from pangea.services.audit.models import PublishedRoot, Root
from pangea.services.audit.signing import Verifier
from pangea.services.audit.util import (
    canonicalize_json,
    decode_consistency_proof,
    decode_hash,
    decode_membership_proof,
    get_arweave_published_roots,
    get_public_key,
    hash_bytes,
    verify_consistency_proof,
    verify_membership_proof,
)

logger = logging.getLogger("audit")
arweave_roots: Dict[int, PublishedRoot] = {}  # roots fetched from Arweave
pangea_roots: Dict[int, Root] = {}  # roots fetched from Pangea
audit: Optional[Audit] = None


class Status(Enum):
    SUCCEEDED = "succeeded"
    SUCCEEDED_PANGEA = "succeeded_pangea"  # succeeded with data fetched from Pangea instead of Arweave
    FAILED = "failed"
    SKIPPED = "skipped"


class VerifierLogFormatter(logging.Formatter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.indent = 0
        self.in_section = False

    def format(self, record):
        if hasattr(record, "is_result"):
            if record.status == Status.SUCCEEDED:
                point = "🟢"
            elif record.status == Status.SUCCEEDED_PANGEA:
                point = "🟡"
            elif record.status == Status.SKIPPED:
                point = "⚪️"
            else:
                point = "🔴"

            self.in_section = False
            return f"{' ' * self.indent}⎿  {record.msg:20s} {point}"

        elif hasattr(record, "is_section"):
            self.in_section = True
            return f"{' ' * self.indent}⎾  {record.msg}"
        else:
            if self.in_section:
                pre = f"{' ' * (self.indent+4)}⌲ "
            else:
                pre = ""
            return f"{pre}{record.msg}"


def log_result(msg: str, status: Status):
    if status == Status.SUCCEEDED:
        msg += " succeeded"
    elif status == Status.SUCCEEDED_PANGEA:
        msg += " succeeded (with data fetched from Pangea)"
    elif status == Status.FAILED:
        msg += " failed"
    else:
        msg += " skipped"
    logger.log(logging.INFO, msg, extra={"is_result": True, "status": status})


def log_section(msg: str):
    logger.log(logging.INFO, msg, extra={"is_section": True})


formatter = VerifierLogFormatter()

InvalidTokenError = ValueError("Invalid Pangea Token provided")


def get_pangea_roots(tree_name: str, tree_sizes: Iterable[int]) -> Dict[int, Root]:
    ans: Dict[int, Root] = {}
    if audit is None:
        return ans

    for size in tree_sizes:
        try:
            resp = audit.root(size)

            if resp.status != "Success":
                raise ValueError(resp.status)
            elif resp.result is None or resp.result.data is None:
                raise ValueError("No result")
            elif resp.result.data.tree_name != tree_name:
                raise InvalidTokenError

            ans[int(size)] = resp.result.data
        except TreeNotFoundException as e:
            ex = InvalidTokenError
            logger.error(f"Error fetching root from Pangea for size {size}: {str(ex)}")
        except Exception as e:
            logger.error(f"Error fetching root from Pangea for size {size}: {str(e)}")
    return ans


def _verify_hash(data: Dict, data_hash: str) -> Status:
    log_section("Checking data hash")
    status = Status.SKIPPED
    try:
        logger.debug("Canonicalizing data")
        data_canon = canonicalize_json(data)
        logger.debug("Calculating hash")
        computed_hash_dec = hash_bytes(data_canon)
        data_hash_dec = decode_hash(data_hash)
        logger.debug("Comparing calculated hash with server hash")
        if computed_hash_dec != data_hash_dec:
            raise ValueError("Hash does not match")
        status = Status.SUCCEEDED
    except Exception:
        status = Status.FAILED

    log_result("Data hash verification", status)
    logger.info("")
    return status


def _verify_unpublished_membership_proof(root_hash, node_hash: str, proof: Optional[str]) -> Status:
    log_section("Checking unpublished membership proof")

    if proof is None:
        status = Status.SKIPPED
        logger.debug("Proof not found")
    else:
        try:
            logger.debug("Decoding hashes")
            root_hash_dec = decode_hash(root_hash)
            node_hash_dec = decode_hash(node_hash)

            logger.debug("Calculating the proof")
            proof_dec = decode_membership_proof(proof)

            logger.debug("Comparing the unpublished root hash with the proof hash")
            if verify_membership_proof(node_hash_dec, root_hash_dec, proof_dec):
                status = Status.SUCCEEDED
            else:
                status = Status.FAILED

        except Exception as e:
            status = Status.FAILED
            logger.debug(str(e))

    log_result("Unpublished membership proof verification", status)
    logger.info("")
    return status


def _fetch_roots(tree_name: str, tree_size: int, leaf_index: Optional[int]) -> Status:
    global arweave_roots, pangea_roots

    log_section("Fetching published roots")

    needed_roots = {tree_size}
    if leaf_index:
        needed_roots |= {leaf_index, leaf_index + 1}

    pending_roots = set()

    def update_pending_roots():
        nonlocal pending_roots
        pending_roots = needed_roots - set(arweave_roots.keys()) - set(pangea_roots.keys())

    def comma_sep(s: Set):
        return ",".join(map(str, s))

    status = Status.SUCCEEDED
    update_pending_roots()

    # print message for roots already fetched
    arweave_fetched_roots = needed_roots & set(arweave_roots.keys())
    if arweave_fetched_roots:
        logger.debug(f"Roots {comma_sep(arweave_fetched_roots)} already fetched from Arweave")

    pangea_fetched_roots = needed_roots & set(pangea_roots.keys())
    if pangea_fetched_roots:
        logger.debug(f"Roots {comma_sep(pangea_fetched_roots)} already fetched from Pangea")
        status = Status.SUCCEEDED_PANGEA

    if pending_roots:
        # try Arweave first
        try:
            logger.debug(f"Fetching root(s) {comma_sep(pending_roots)} from Arweave")
            arweave_roots |= {int(k): v for k, v in get_arweave_published_roots(tree_name, pending_roots).items()}
            update_pending_roots()
        except:
            pass

    if pending_roots:
        logger.debug(f"Published root(s) {comma_sep(pending_roots)} could not be fetched from Arweave")

    if pending_roots:
        if audit:
            # and then Pangea (if we've set an audit client)
            try:
                logger.debug(f"Fetching root(s) {comma_sep(pending_roots)} from Pangea")
                pangea_roots |= {int(k): v for k, v in get_pangea_roots(tree_name, pending_roots).items()}
                update_pending_roots()
                status = Status.SUCCEEDED_PANGEA
            except:
                pass

            if pending_roots:
                logger.debug(f"Roots {comma_sep(pending_roots)} could not be fetched")
        else:
            logger.debug("Set Pangea token and domain (from envvars or script parameters) to fetch roots from Pangea")

    if pending_roots:
        status = Status.FAILED

    log_result("Fetching published roots", status)
    logger.info("")
    return status


def _verify_membership_proof(tree_size: int, node_hash: str, proof: Optional[str]) -> Status:
    pub_roots: Dict[int, Union[Root, PublishedRoot]] = arweave_roots | pangea_roots

    log_section("Checking membership proof")

    if tree_size not in pub_roots:
        status = Status.SKIPPED
        logger.debug("Published root not found")
    elif proof is None:
        status = Status.SKIPPED
        logger.debug("Proof not found (event not published yet)")
    else:
        try:
            root_hash_dec = decode_hash(pub_roots[tree_size].root_hash)
            node_hash_dec = decode_hash(node_hash)
            logger.debug("Calculating the proof")
            if proof is None:
                logger.debug("Consistency proof is missing")
                return False
            proof_dec = decode_membership_proof(proof)
            logger.debug("Comparing the root hash with the proof hash")
            if verify_membership_proof(node_hash_dec, root_hash_dec, proof_dec):
                status = Status.SUCCEEDED
            else:
                status = Status.FAILED
        except Exception as e:
            status = Status.FAILED
            logger.debug(str(e))

    log_result("Membership proof verification", status)
    logger.info("")
    return status


def _consistency_proof_ok(pub_roots: Dict[int, Union[Root, PublishedRoot]], leaf_index: int) -> bool:
    """returns true if a consistency proof is correct"""

    curr_root = pub_roots[leaf_index + 1]
    prev_root = pub_roots[leaf_index]
    curr_root_hash = decode_hash(curr_root.root_hash)
    prev_root_hash = decode_hash(prev_root.root_hash)
    if curr_root.consistency_proof is None:
        logger.debug("Consistency proof is missing")
        return False

    logger.debug("Calculating the proof")
    proof = decode_consistency_proof(curr_root.consistency_proof)
    return verify_consistency_proof(curr_root_hash, prev_root_hash, proof)


# Due to an (already fixed) bug, some proofs from Arweave may be wrong.
# Try the proof from Pangea instead. If the root hash in both Arweave and Pangea is the same,
# it doesn't matter where the proof came from.
def _fix_consistency_proof(pub_roots: Dict[int, Union[Root, PublishedRoot]], tree_name: str, leaf_index: int):
    logger.debug("Consistency proof from Arweave failed to verify")
    size = leaf_index + 1
    logger.debug(f"Fetching root from Pangea for size {size}")
    new_roots = get_pangea_roots(tree_name, [size])
    if size not in new_roots:
        raise ValueError("Error fetching root from Pangea")
    pangea_roots[size] = new_roots[size]
    pub_roots[size] = pangea_roots[size]
    logger.debug(f"Comparing Arweave root hash with Pangea root hash")
    if pangea_roots[size].root_hash != arweave_roots[size].root_hash:
        raise ValueError("Hash does not match")


def _verify_consistency_proof(tree_name: str, leaf_index: Optional[int]) -> Status:
    pub_roots: Dict[int, Union[Root, PublishedRoot]] = arweave_roots | pangea_roots

    log_section("Checking consistency proof")

    if leaf_index is None:
        status = Status.SKIPPED
        logger.debug("Proof not found (event was not published yet)")

    elif leaf_index == 0:
        status = Status.SKIPPED
        logger.debug("Proof not found (event was published in the first leaf)")

    elif leaf_index not in pub_roots:
        status = Status.SKIPPED
        logger.debug("Published root not found")

    else:
        try:
            if _consistency_proof_ok(pub_roots, leaf_index):
                status = Status.SUCCEEDED

            elif audit:
                _fix_consistency_proof(pub_roots, tree_name, leaf_index)

                # check again
                if _consistency_proof_ok(pub_roots, leaf_index):
                    status = Status.SUCCEEDED
                else:
                    status = Status.FAILED

            else:
                logger.debug(
                    "Set Pangea token and domain (from envvars or script parameters) to fetch roots from Pangea"
                )
                status = Status.FAILED

        except Exception as e:
            status = Status.FAILED
            logger.debug(str(e))

    log_result("Consistency proof verification", status)
    logger.info("")
    return status


def create_signed_event(event: Dict) -> Dict:
    return {k: v for k, v in event.items() if v is not None}


def _verify_signature(data: Dict) -> Status:
    log_section("Checking signature")
    if "signature" not in data:
        logger.debug("Signature is not present")
        status = Status.SKIPPED
    else:
        try:
            logger.debug("Obtaining signature and public key from the event")
            sign_event = create_signed_event(data["event"])
            public_key = get_public_key(data["public_key"])
            sign_verifier = Verifier()
            logger.debug("Checking the signature")
            if not sign_verifier.verify_signature(data["signature"], canonicalize_json(sign_event), public_key):
                raise ValueError("Signature is invalid")
            status = Status.SUCCEEDED
        except Exception:
            status = Status.FAILED

    log_result("Data signature verification", status)
    logger.info("")
    return status


def verify_multiple(root: Dict, unpublished_root: Dict, events: List[Dict]) -> Status:
    """
    Verify a list of events.
    Returns a status.
    """

    statuses: List[Status] = []
    for counter, event in enumerate(events):
        event.update({"root": root, "unpublished_root": unpublished_root})
        event_status = verify_single(event, counter + 1)
        statuses.append(event_status)

    for event_status in statuses:
        if event_status == Status.FAILED:
            return Status.FAILED
        elif event_status == Status.SKIPPED:
            return Status.SKIPPED
    return Status.SUCCEEDED


def verify_single(data: Dict, counter: Optional[int] = None) -> Status:
    """
    Verify a single event.
    Returns a status.
    """
    if counter:
        logger.info(f"Checking event number {counter}...")
        formatter.indent = 4

    ok_hash = _verify_hash(data["envelope"], data["hash"])
    ok_signature = _verify_signature(data["envelope"])

    if data.get("root"):
        ok_roots = _fetch_roots(data["root"]["tree_name"], data["root"]["size"], data.get("leaf_index"))
    else:
        ok_roots = Status.SKIPPED

    if data["published"]:
        if not data.get("root"):
            raise ValueError("Missing 'root' element")
        ok_membership = _verify_membership_proof(
            data["root"]["size"],
            data["hash"],
            data.get("membership_proof"),
        )
    else:
        if not data.get("unpublished_root"):
            raise ValueError("Missing 'unpublished_root' element")
        ok_membership = _verify_unpublished_membership_proof(
            data["unpublished_root"]["root_hash"], data["hash"], data.get("membership_proof")
        )

    if data["published"]:
        ok_consistency = _verify_consistency_proof(data["root"]["tree_name"], data.get("leaf_index"))
    else:
        ok_consistency = Status.SUCCEEDED

    all_ok = (
        ok_hash == Status.SUCCEEDED
        and (ok_signature in (Status.SUCCEEDED, Status.SKIPPED))
        and (ok_roots in (Status.SKIPPED, Status.SUCCEEDED, Status.SUCCEEDED_PANGEA))
        and ok_membership == Status.SUCCEEDED
        and (ok_consistency in (Status.SUCCEEDED, Status.SKIPPED))
    )
    any_failed = (
        ok_hash == Status.FAILED
        or (ok_signature == Status.FAILED)
        or (ok_membership == Status.FAILED)
        or (ok_consistency == Status.FAILED)
    )

    if counter:
        formatter.indent = 0

    if all_ok:
        return Status.SUCCEEDED
    elif any_failed:
        return Status.FAILED
    else:
        return Status.SKIPPED


def main():
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    parser = argparse.ArgumentParser(description="Pangea Audit Verifier")
    parser.add_argument(
        "--file",
        "-f",
        type=argparse.FileType("r"),
        default=sys.stdin,
        metavar="PATH",
        help="Input file (default: standard input).",
    )
    parser.add_argument(
        "--token", "-t", default=os.getenv("PANGEA_TOKEN"), help="Pangea token (default: env PANGEA_TOKEN)"
    )
    parser.add_argument(
        "--domain", "-d", default=os.getenv("PANGEA_DOMAIN"), help="Pangea domain (default: env PANGEA_DOMAIN)"
    )
    args = parser.parse_args()

    data = json.load(args.file)
    events = data.get("result", {}).get("events", [])

    logger.info("Pangea Audit - Verification Tool")
    logger.info("")

    if args.token and args.domain:
        global audit
        audit = Audit(token=args.token, config=PangeaConfig(domain=args.domain))

    if events:
        status = verify_multiple(data["result"].get("root"), data["result"].get("unpublished_root"), events)
    else:
        status = verify_single(data)

    logger.info("")
    if status == Status.SUCCEEDED:
        logger.info("🟢 Verification succeeded 🟢")
    elif status == Status.FAILED:
        logger.info("🔴 Verification failed 🔴")
    else:
        logger.info("⚪️ Verification could not be finished ⚪️")
    logger.info("")

    return 0 if status is not False else 1


if __name__ == "__main__":
    main()

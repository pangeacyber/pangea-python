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
import sys
import os
from enum import Enum
from typing import Dict, List, Optional

from pangea.config import PangeaConfig
from pangea.services.audit.signing import Verifier
from pangea.services import Audit
from pangea.services.audit.models import Root
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
    PublishedRoot,
)

logger = logging.getLogger("audit")
pub_roots: Dict[int, Dict] = {}
audit: Audit


class VerifierLogFormatter(logging.Formatter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.indent = 0
        self.in_section = False

    def format(self, record):
        if hasattr(record, "is_result"):
            if record.succeeded:
                point = "🟢"
            elif record.succeeded is None:
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


def log_result(msg: str, succeeded: Optional[bool]):
    if succeeded is True:
        msg += " succeeded"
    elif succeeded is False:
        msg += " failed"
    else:
        msg += " could not be performed"
    logger.log(logging.INFO, msg, extra={"is_result": True, "succeeded": succeeded})


def log_section(msg: str):
    logger.log(logging.INFO, msg, extra={"is_section": True})


formatter = VerifierLogFormatter()


def _get_roots(tree_sizes: List[int]) -> Dict[int, Root]:
    ans = {}
    for size in tree_sizes:
        try:
            resp = audit.root(size)
            if resp.status != "Success":
                raise ValueError(resp.Status)

            ans[int(size)] = resp.result.data
        except Exception as e:
            logger.error(f"Error fetching root from Pangea for size {size}: {str(e)}")
    return ans


def _verify_hash(data: Dict, data_hash: str) -> Optional[bool]:
    log_section("Checking data hash")
    try:
        logger.debug("Canonicalizing data")
        data_canon = canonicalize_json(data)
        logger.debug("Calculating hash")
        computed_hash_dec = hash_bytes(data_canon)
        data_hash_dec = decode_hash(data_hash)
        logger.debug("Comparing calculated hash with server hash")
        if computed_hash_dec != data_hash_dec:
            raise ValueError("Hash does not match")
        succeeded = True
    except Exception:
        succeeded = False

    log_result("Data hash verification", succeeded)
    logger.info("")
    return succeeded


def _verify_unpublished_membership_proof(root_hash, node_hash: str, proof: Optional[str]) -> Optional[bool]:
    global pub_roots

    log_section("Checking unpublished membership proof")

    if proof is None:
        succeeded = None
        logger.debug("Proof not found")
    else:
        try:
            logger.debug("Decoding hashes")
            root_hash_dec = decode_hash(root_hash)
            node_hash_dec = decode_hash(node_hash)

            logger.debug("Calculating the proof")
            proof_dec = decode_membership_proof(proof)

            logger.debug("Comparing the unpublished root hash with the proof hash")
            succeeded = verify_membership_proof(node_hash_dec, root_hash_dec, proof_dec)

        except Exception as e:
            succeeded = False
            logger.debug(str(e))

    log_result("Unpublished membership proof verification", succeeded)
    logger.info("")
    return succeeded


def _fetch_roots(tree_name: str, tree_size: int, leaf_index: Optional[int]) -> Optional[bool]:
    global pub_roots

    log_section("Fetching published roots from Arweave")

    succeeded = None
    needed_roots = {tree_size}
    if leaf_index:
        needed_roots |= {leaf_index, leaf_index + 1}
    pending_roots = needed_roots - set(pub_roots.keys())

    try:
        if pending_roots:
            pub_roots |= {int(k): v for k, v in get_arweave_published_roots(tree_name, pending_roots).items()}  # type: ignore[operator]
            pending_roots = needed_roots - set(pub_roots.keys())
        succeeded = True
        if pending_roots and audit:
            logger.debug("Published root could not be fetched from Arweave")
            logger.debug("Fetching published roots from Pangea")
            pub_roots |= {int(k): v for k, v in _get_roots(pending_roots).items()}  # type: ignore[operator]
            pending_roots = needed_roots - set(pub_roots.keys())
            succeeded = None
        if pending_roots:
            raise ValueError("Published root could not be fetched")
    except:
        succeeded = False

    log_result("Fetching published roots", succeeded)
    logger.info("")
    return succeeded


def _verify_membership_proof(tree_size: int, node_hash: str, proof: Optional[str]) -> Optional[bool]:
    global pub_roots

    log_section("Checking membership proof")

    if tree_size not in pub_roots:
        succeeded = None
        logger.debug("Published root not found")
    elif proof is None:
        succeeded = None
        logger.debug("Proof not found (event not published yet)")
    else:
        try:
            root_hash_dec = decode_hash(pub_roots[tree_size].root_hash)  # type: ignore[attr-defined]
            node_hash_dec = decode_hash(node_hash)
            logger.debug("Calculating the proof")
            proof_dec = decode_membership_proof(proof)
            logger.debug("Comparing the root hash with the proof hash")
            succeeded = verify_membership_proof(node_hash_dec, root_hash_dec, proof_dec)
        except Exception as e:
            succeeded = False
            logger.debug(str(e))

    log_result("Membership proof verification", succeeded)
    logger.info("")
    return succeeded


def _verify_consistency_proof(leaf_index: Optional[int]) -> Optional[bool]:
    global pub_roots
    log_section("Checking consistency proof")

    if leaf_index is None:
        succeeded = None
        logger.debug("Proof not found (event was not published yet)")

    elif leaf_index == 0:
        succeeded = None
        logger.debug("Proof not found (event was published in the first leaf)")

    elif leaf_index not in pub_roots:
        succeeded = None
        logger.debug("Published root not found")
    
    else:
        try:
            curr_root = pub_roots[leaf_index + 1]
            prev_root = pub_roots[leaf_index]
            curr_root_hash = decode_hash(curr_root.root_hash)  # type: ignore[attr-defined]
            prev_root_hash = decode_hash(prev_root.root_hash)  # type: ignore[attr-defined]
            logger.debug("Calculating the proof")
            proof = decode_consistency_proof(curr_root.consistency_proof)  # type: ignore[attr-defined]
            succeeded = verify_consistency_proof(curr_root_hash, prev_root_hash, proof)

        except Exception as e:
            succeeded = False
            logger.debug(str(e))

    log_result("Consistency proof verification", succeeded)
    logger.info("")
    return succeeded


def create_signed_event(event: Dict) -> Dict:
    return {k: v for k, v in event.items() if v is not None}


def _verify_signature(data: Dict) -> Optional[bool]:
    log_section("Checking signature")
    if "signature" not in data:
        logger.debug("Signature is not present")
        succeeded = None
    else:
        try:
            logger.debug("Obtaining signature and public key from the event")
            sign_event = create_signed_event(data["event"])
            public_key = get_public_key(data["public_key"])
            sign_verifier = Verifier()
            logger.debug("Checking the signature")
            if not sign_verifier.verify_signature(data["signature"], canonicalize_json(sign_event), public_key):
                raise ValueError("Signature is invalid")
            succeeded = True
        except Exception:
            succeeded = False

    log_result("Data signature verification", succeeded)
    logger.info("")
    return succeeded


def verify_multiple(root: Dict, unpublished_root: Dict, events: List[Dict]) -> Optional[bool]:
    """
    Verify a list of events.
    Returns a status.
    """

    succeeded = []
    for counter, event in enumerate(events):
        event.update({"root": root, "unpublished_root": unpublished_root})
        event_succeeded = verify_single(event, counter + 1)
        succeeded.append(event_succeeded)

    for event_succeeded in succeeded:
        if event_succeeded is False:
            return False
        elif event_succeeded is None:
            return None
    return True


def verify_single(data: Dict, counter: Optional[int] = None) -> Optional[bool]:
    """
    Verify a single event.
    Returns a status.
    """
    if counter:
        logger.info(f"Checking event number {counter}...")
        formatter.indent = 4

    ok_hash = _verify_hash(data["envelope"], data["hash"])
    ok_signature = _verify_signature(data["envelope"])

    ok_roots = _fetch_roots(data["root"]["tree_name"], data["root"]["size"], data.get("leaf_index"))

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
        ok_consistency = _verify_consistency_proof(data.get("leaf_index"))
    else:
        ok_consistency = True

    all_ok = (
        ok_hash is True
        and (ok_signature is True or ok_signature is None)
        and (ok_roots is True or ok_roots is None)
        and ok_membership is True
        and (ok_consistency is True or ok_consistency is None)
    )
    any_failed = (
        ok_hash is False 
        or (ok_signature is False)
        or (ok_membership is False)
        or (ok_consistency is False)
    )

    if counter:
        formatter.indent = 0

    if all_ok:
        return True
    elif any_failed:
        return False
    else:
        return None


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
    if status is True:
        logger.info("🟢 Verification succeeded 🟢")
    elif status is False:
        logger.info("🔴 Verification failed 🔴")
    else:
        logger.info("⚪️ Verification could not be finished ⚪️")
    logger.info("")

    return 0 if status is not False else 1


if __name__ == "__main__":
    main()

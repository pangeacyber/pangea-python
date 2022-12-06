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
import typing as t

from pangea.services.audit.signing import Verifier
from pangea.services.audit.util import (
    canonicalize_json,
    decode_consistency_proof,
    decode_hash,
    decode_membership_proof,
    get_arweave_published_roots,
    hash_bytes,
    verify_consistency_proof,
    verify_membership_proof,
)

logger = logging.getLogger("audit")
pub_roots: t.Dict[int, t.Dict] = {}


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


def log_result(msg: str, succeeded: t.Optional[bool]):
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


def _verify_hash(data: t.Dict, data_hash: str) -> t.Optional[bool]:
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


def _verify_unpublished_membership_proof(
    root_hash, node_hash: str, proof: t.Optional[str]
) -> t.Optional[bool]:
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


def _verify_membership_proof(
    tree_name: str, tree_size: int, node_hash: str, proof: t.Optional[str]
) -> t.Optional[bool]:
    global pub_roots

    log_section("Checking membership proof")

    if proof is None:
        succeeded = None
        logger.debug("Proof not found (event not published yet)")
    else:
        try:
            logger.debug("Fetching published roots from Arweave")
            if tree_size not in pub_roots:
                pub_roots |= {int(k): v for k, v in get_arweave_published_roots(tree_name, [tree_size]).items()}
            if tree_size not in pub_roots:
                raise ValueError("Published root could was not found")

            root_hash_dec = decode_hash(pub_roots[tree_size].root_hash)
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


def _verify_consistency_proof(tree_name: str, leaf_index: t.Optional[int]) -> t.Optional[bool]:
    global pub_roots
    log_section("Checking consistency proof")

    if leaf_index is None:
        succeeded = None
        logger.debug("Proof not found (event was not published yet)")

    elif leaf_index == 0:
        succeeded = None
        logger.debug("Proof not found (event was published in the first leaf)")
    else:
        try:
            logger.debug("Fetching published roots from Arweave")
            pub_roots |= {
                int(k): v for k, v in get_arweave_published_roots(tree_name, [leaf_index + 1, leaf_index]).items()
            }
            if leaf_index + 1 not in pub_roots or leaf_index not in pub_roots:
                raise ValueError("Published roots could not be retrieved")

            curr_root = pub_roots[leaf_index + 1]
            prev_root = pub_roots[leaf_index]
            curr_root_hash = decode_hash(curr_root.root_hash)
            prev_root_hash = decode_hash(prev_root.root_hash)
            logger.debug("Calculating the proof")
            proof = decode_consistency_proof(curr_root.consistency_proof)
            succeeded = verify_consistency_proof(curr_root_hash, prev_root_hash, proof)

        except Exception as e:
            succeeded = False
            logger.debug(str(e))

    log_result("Consistency proof verification", succeeded)
    logger.info("")
    return succeeded


def create_signed_envelope(event: t.Dict) -> t.Dict:
    return {k: v for k, v in event.items() if v is not None}


def _verify_signature(data: t.Dict) -> t.Optional[bool]:
    log_section("Checking signature")
    if "signature" not in data:
        logger.debug("Signature is not present")
        succeeded = None
    else:
        try:
            logger.debug("Obtaining signature and public key from the event")
            sign_envelope = create_signed_envelope(data["event"])
            public_key_b64 = data["public_key"]
            sign_verifier = Verifier()
            logger.debug("Checking the signature")
            if not sign_verifier.verifyMessage(data["signature"], sign_envelope, public_key_b64):
                raise ValueError("Signature is invalid")
            succeeded = True
        except Exception:
            succeeded = False

    log_result("Data signature verification", succeeded)
    logger.info("")
    return succeeded


def verify_multiple(root: t.Dict, unpublished_root: t.Dict, events: t.List[t.Dict]) -> t.Optional[bool]:
    """
    Verify a list of events.
    Returns a status.
    """

    succeeded = []
    for counter, event in enumerate(events):
        event.update({
            "root": root,
            "unpublished_root": unpublished_root
        })
        event_succeeded = verify_single(event, counter + 1)
        succeeded.append(event_succeeded)
    return not any(event_succeeded is False for event_succeeded in succeeded)


def verify_single(data: t.Dict, counter: t.Optional[int] = None) -> t.Optional[bool]:
    """
    Verify a single event.
    Returns a status.
    """
    if counter:
        logger.info(f"Checking event number {counter}...")
        formatter.indent = 4

    ok_hash = _verify_hash(data["envelope"], data["hash"])
    ok_signature = _verify_signature(data["envelope"])

    if data["published"]:
        if not data.get("root"):
            raise ValueError("Missing 'root' element")
        ok_membership = _verify_membership_proof(
            data["root"]["tree_name"],
            data["root"]["size"],
            data["hash"],
            data.get("membership_proof"),
        )
    else:
        if not data.get("unpublished_root"):
            raise ValueError("Missing 'unpublished_root' element")
        ok_membership = _verify_unpublished_membership_proof(
            data["unpublished_root"]["root_hash"],
            data["hash"],
            data.get("membership_proof")
        )

    if data["published"]:
        ok_consistency = _verify_consistency_proof(data["root"]["tree_name"], data.get("leaf_index"))
    else:
        ok_consistency = True

    all_ok = ok_hash is True and (ok_signature is True or ok_signature is None) and ok_membership is True and ok_consistency is True
    any_failed = ok_hash is False or ok_signature is False or ok_membership is False or ok_consistency is False

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
    args = parser.parse_args()

    data = json.load(args.file)
    events = data.get("result", {}).get("events", [])

    logger.info("Pangea Audit - Verification Tool")
    logger.info("")

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

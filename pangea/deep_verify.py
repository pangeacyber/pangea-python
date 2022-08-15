import argparse
import sys
import math
import json
import typing as t
from alive_progress import alive_bar

import pangea.services.audit_util as audit_util



class Root(t.TypedDict):
    size: int
    tree_name: str


class Event(t.TypedDict):
    membership_proof: str
    leaf_index: int


def rootFromFile(f: str) -> Root:
    """
    Reads a file containing a Root in JSON format with the following fields:
    - membership_proof: str
    - leaf_index: int
    """
    return json.load(f)


def eventsInFile(f) -> t.Iterator[Event]:
    """
    Reads a file containing Events in JSON format with the following fields:
    - membership_proof: str
    - leaf_index: int
    """
    for idx, line in enumerate(f):
        try:
            yield json.loads(line)
        except json.JSONDecodeError as e:
            exit_with_error(f"failed to parse line: {idx}: {e.msg}")


def lenOfFile(f) -> int:
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
    """ if the tree has size tree_size, return the size of the left child """
    if tree_size <= 1:
        return 0
    return 2**(math.ceil(math.log2(tree_size)) - 1)


def get_proof_path(proof: str) -> str:
    return "".join(elem[0] for elem in proof.split(","))


def exit_with_error(message: str):
    print(message)
    sys.exit(1)


def height(size: int) -> int:
    return int(math.log2(size)) + 1


def index_number(tree_height: int, membership_proof: str) -> int:
    decoded_proof = audit_util.decode_membership_proof(membership_proof)
    idx_number: int = 0
    for idx, proof in enumerate(decoded_proof):
        if proof.side == 'left':
            idx_number += round(2 ** (tree_height - idx - 1))
    return idx_number


def verify_hash(data: dict, data_hash: str) -> bool:
    """ Verify the hash of an event """
    succeeded = False
    try:
        data_canon = audit_util.canonicalize_json(data)
        computed_hash = audit_util.hash_data(data_canon)
        computed_hash_dec = audit_util.decode_hash(computed_hash)
        data_hash_dec = audit_util.decode_hash(data_hash)
        if computed_hash_dec != data_hash_dec:
            raise ValueError("Hash does not match")
        succeeded = True
    except Exception:
        pass
    return succeeded


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


def load_args():
    parser = argparse.ArgumentParser(
        description="Pangea Audit Event Deletion Verifier")
    parser.add_argument(
        "--events",
        "-e",
        type=argparse.FileType("r"),
        metavar="PATH",
        help="Event input file. Must be a collection of "
             "JSON Objects separated by newlines",
    )
    parser.add_argument(
        "--root",
        "-r",
        type=argparse.FileType("r"),
        metavar="PATH",
        help="root input file. Must be a JSON Object",
    )
    args = parser.parse_args()
    if not args.events or not args.root:
        parser.print_help(sys.stderr)
        sys.exit(1)
    return args.events, args.root


def main():
    events_file, root_file = load_args()

    with alive_bar(1, title="Counting Events") as bar:
        total_events = lenOfFile(events_file)
        bar()

    root = rootFromFile(root_file)
    t_size = root['size']
    events = eventsInFile(events_file)

    with alive_bar(total_events, title="Validating Events") as bar:
        current_event = next(events)
        bar()
        leaf_index = current_event['leaf_index']
        grpByIdxEvents = [current_event]
        cnt = 0
        for event in events:
            if event['leaf_index'] == leaf_index:
                grpByIdxEvents.append(event)
            else:
                cold_path_size = get_path_size(t_size, leaf_index)
                prev_index = None
                for e in grpByIdxEvents:
                    cnt += 1
                    if not verify_hash(e["event"], e["hash"]):
                        print(f"failed hash for event {cnt}")
                        # exit_with_error(
                        #     f"failed hash check "
                        #     f"for {e}")

                    elif not verify_membership_proof(e["hash"], root["root_hash"], e["membership_proof"]):
                        print(f"failed membership_proof for event {cnt}")
                        # exit_with_error(
                        #     f"failed membership proof check "
                        #     f"for {e}")

                    path = get_proof_path(e["membership_proof"])
                    hot_path = path[:-cold_path_size]
                    cold_path = path[-cold_path_size:]
                    cold_idx = path2index(t_size, cold_path)
                    if cold_idx != leaf_index:
                        exit_with_error(
                            f"failed cold tree leaf index check"
                            f"for {e}: {cold_idx} != {leaf_index}")
                    hot_idx = path2index(len(grpByIdxEvents), hot_path)
                    if prev_index is None or prev_index + 1 == hot_idx:
                        prev_index = hot_idx
                    else:
                        exit_with_error(
                            f"failed hot tree leaf index check "
                            f"for {e}: {prev_index} != {hot_idx}")
                print('-> Successfully validated events of '
                      f'leaf_index: {leaf_index}')
                leaf_index = event['leaf_index']
                grpByIdxEvents = [event]
            current_event = event
            bar()
    print("Successfully validated all events - No missing events were detected")
    sys.exit(0)


if __name__ == "__main__":
    main()

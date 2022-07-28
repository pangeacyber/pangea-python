import sys
import math
import json
import typing as t

import pangea.services.audit_util as audit_util


class Root(t.TypedDict):
    size: int
    tree_name: str


class Event(t.TypedDict):
    membership_proof: str
    leaf_index: int


def rootFromFile(file_path: str) -> Root:
    """
    Reads a file containing a Root in JSON format with the following fields:
    - membership_proof: str
    - leaf_index: int
    """
    with open(file_path) as f:
        return json.load(f)


def eventsInFile(file_path: str) -> t.Iterator[Event]:
    """
    Reads a file containing Events in JSON format with the following fields:
    - membership_proof: str
    - leaf_index: int
    """
    with open(file_path) as f:
        for idx, line in enumerate(f):
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                exit_with_error(f"failed to parse line: {idx}: {e.msg}")


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


def main():
    root = rootFromFile("./root.txt")
    t_size = root['size']
    events = eventsInFile("./test.txt")
    current_event = next(events)
    leaf_index = current_event['leaf_index']
    grpByIdxEvents = [current_event]
    for event in events: 
        if event['leaf_index'] == leaf_index:
            grpByIdxEvents.append(event)
        else:
            cold_path_size = get_path_size(t_size, leaf_index)
            prev_index = None
            for e in grpByIdxEvents:
                path = get_proof_path(e["membership_proof"])
                hot_path = path[:-cold_path_size]
                cold_path = path[-cold_path_size:]
                if cold_idx := path2index(t_size, cold_path) != leaf_index:
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
            leaf_index = event['leaf_index']
            grpByIdxEvents = [event]
        current_event = event
    print("succefully verified all events")
    sys.exit(0)


if __name__ == "__main__":
    main()

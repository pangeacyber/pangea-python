# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import io
import json
import os
import sys
import typing as t
from datetime import datetime, timezone

from pangea.config import PangeaConfig
from pangea.services import Audit


class Root(t.TypedDict):
    size: int
    tree_name: str


class Event(t.TypedDict):
    membership_proof: str
    leaf_index: t.Optional[int]
    event: dict
    hash: str
    tree_size: t.Optional[int]


def print_progress_bar(iteration, total, prefix="", suffix="", decimals=1, length=100):
    if length <= 0:
        length = 100

    if iteration < 0 or total <= 0:
        iteration = 1
        total = 1
    else:
        iteration = min(iteration, total)

    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = "█" * filledLength + "-" * (length - filledLength)
    print(f"\r{prefix} |{bar}| {percent}% {suffix}", end="\r")
    # if iteration == total:
    #     print()


def get_script_name() -> str:
    return os.path.split(sys.argv[0])[-1]


def exit_with_error(message: str):
    print(f"{get_script_name()}: error: {message}")
    sys.exit(1)


def file_events(root_hashes: dict[int, str], f: io.TextIOWrapper) -> t.Iterator[Event]:
    """
    Reads a file containing Events in JSON format with the following fields:
    - membership_proof: str
    - leaf_index: int
    """
    for idx, line in enumerate(f):
        try:
            data = json.loads(line)
            if "envelope" in data:
                # single event (from PUC or dump file in jsonl format)
                if "root" in data:
                    # artifact from PUC
                    root = data["root"]
                    root_hashes[root["size"]] = root["root_hash"]
                    data["tree_size"] = root["size"]
                yield data
            elif "request_id" in data:
                # result from a search
                root = data["result"]["root"]
                root_hashes[root["size"]] = root["root_hash"]
                for event in data["result"]["events"]:
                    event["tree_size"] = root["size"]
                    yield event
            else:
                raise ValueError("invalid data")
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            exit_with_error(f"failed to parse line {idx}: {str(e)}")


def init_audit(token: str, domain: str, config_id: str = "") -> Audit:
    config = PangeaConfig(domain=domain, config_id=config_id)
    audit = Audit(token, config=config)
    return audit


def make_aware_datetime(d: datetime) -> datetime:
    if d.tzinfo is None or d.tzinfo.utcoffset(d) is None:
        return d.replace(tzinfo=timezone.utc)
    else:
        return d


class SequenceFollower:
    """
    Follows an unordered sequence of integers, looking for holes
    """

    def __init__(self):
        self.numbers = set()

    def add(self, val: int):
        self.numbers.add(val)
        self._reduce()

    def _reduce(self):
        """remove consecutive numbers from the left"""
        min_val = min(self.numbers)
        while min_val + 1 in self.numbers:
            self.numbers.remove(min_val)
            min_val += 1

    def holes(self) -> list[int]:
        if not self.numbers:
            return []

        min_val = min(self.numbers)
        max_val = max(self.numbers)
        return [val for val in range(min_val, max_val) if val not in self.numbers]

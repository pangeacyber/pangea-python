# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import enum
import io
import json
import logging
import os
import sys
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from typing import Dict, Iterator, List, Optional

from pangea.config import PangeaConfig
from pangea.exceptions import PangeaException
from pangea.services import Audit


class TestEnvironment(str, enum.Enum):
    DEVELOP = "DEV"
    LIVE = "LVE"
    STAGING = "STG"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class Root(Dict):
    size: int
    tree_name: str


class Event(Dict):
    membership_proof: str
    leaf_index: Optional[int]
    event: Dict
    hash: str
    tree_size: Optional[int]


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


def file_events(root_hashes: Dict[int, str], f: io.TextIOWrapper) -> Iterator[Event]:
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
            exit_with_error(f"failed to parse line {idx}: {e!s}")


def init_audit(token: str, domain: str) -> Audit:
    config = PangeaConfig(domain=domain)
    audit = Audit(token, config=config, logger_name="audit")
    logger_set_pangea_config(logger_name=audit.logger.name)
    return audit


def make_aware_datetime(d: datetime) -> datetime:
    if d.tzinfo is None or d.tzinfo.utcoffset(d) is None:
        return d.replace(tzinfo=timezone.utc)
    return d


def filter_deep_none(data: Dict) -> Dict:
    return {k: v if not isinstance(v, Dict) else filter_deep_none(v) for k, v in data.items() if v is not None}


def _load_env_var(env_var_name: str) -> str:
    value = os.getenv(env_var_name)
    if not value:
        raise PangeaException(f"{env_var_name} env var need to be set")

    return value


def get_test_domain(environment: TestEnvironment) -> str:
    env_var_name = f"PANGEA_INTEGRATION_DOMAIN_{environment}"
    return _load_env_var(env_var_name)


def get_test_token(environment: TestEnvironment) -> str:
    env_var_name = f"PANGEA_INTEGRATION_TOKEN_{environment}"
    return _load_env_var(env_var_name)


def get_vault_signature_test_token(environment: TestEnvironment):
    env_var_name = f"PANGEA_INTEGRATION_VAULT_TOKEN_{environment}"
    return _load_env_var(env_var_name)


def get_multi_config_test_token(environment: TestEnvironment):
    env_var_name = f"PANGEA_INTEGRATION_MULTI_CONFIG_TOKEN_{environment}"
    return _load_env_var(env_var_name)


def get_config_id(environment: TestEnvironment, service: str, config_number: int):
    service = service.upper()
    env_var_name = f"PANGEA_{service}_CONFIG_ID_{config_number}_{environment}"
    return _load_env_var(env_var_name)


def get_custom_schema_test_token(environment: TestEnvironment):
    env_var_name = f"PANGEA_INTEGRATION_CUSTOM_SCHEMA_TOKEN_{environment}"
    value = os.getenv(env_var_name)
    if not value:
        raise PangeaException(f"{env_var_name} env var need to be set")

    return value


def get_custom_schema_vault_test_token(environment: TestEnvironment):
    env_var_name = f"PANGEA_INTEGRATION_CUSTOM_SCHEMA_TOKEN_{environment}"
    value = os.getenv(env_var_name)
    if not value:
        raise PangeaException(f"{env_var_name} env var need to be set")

    return value


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

    def holes(self) -> List[int]:
        if not self.numbers:
            return []

        min_val = min(self.numbers)
        max_val = max(self.numbers)
        return [val for val in range(min_val, max_val) if val not in self.numbers]


loggers: Dict[str, bool] = {}


def logger_set_pangea_config(logger_name: str, level=logging.DEBUG):
    if loggers.get(logger_name) is not None:
        return

    loggers[logger_name] = True
    logger = logging.getLogger(logger_name)
    logger.setLevel(level)
    handler = TimedRotatingFileHandler(
        filename="pangea_sdk_logs.json", when="D", interval=1, backupCount=90, encoding="utf-8", delay=False
    )
    handler.setLevel(level)
    formatter = logging.Formatter(
        fmt='{"time": "%(asctime)s.%(msecs)03d", "name": "%(name)s", "level": "%(levelname)s",  "message": %(message)s },',
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

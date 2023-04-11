import base64
import collections as c
import copy
import datetime
import json


def format_datetime(dt: datetime.datetime) -> str:
    """
    Format a datetime in ISO format, using Z instead of +00:00
    """
    if dt.tzinfo is None:
        dt = dt.astimezone(datetime.timezone.utc)
    return dt.isoformat(timespec="microseconds").replace("+00:00", "Z")


def default_encoder(obj) -> str:
    if isinstance(obj, datetime.datetime):
        return format_datetime(obj)
    if isinstance(obj, datetime.date):
        return str(obj)
    if isinstance(obj, dict):
        print("encoder canonicalize obj")
        return canonicalize(obj)
    else:
        return str(obj)


def str2str_b64(data: str):
    return base64.b64encode(data.encode("ascii")).decode("ascii")


def dict_order_keys(data: dict) -> c.OrderedDict:
    if isinstance(data, dict):
        return c.OrderedDict(sorted(data.items()))
    else:
        return data


def dict_order_keys_recursive(data: dict) -> c.OrderedDict:
    if isinstance(data, dict):
        for k, v in data.items():
            if type(v) is dict:
                data[k] = dict_order_keys_recursive(v)

    return data


def canonicalize_nested_json(data: dict) -> dict:
    """Canonicalize nested JSON"""
    if not isinstance(data, dict):
        return data

    datacp = copy.deepcopy(data)
    for k, v in datacp.items():
        if isinstance(v, dict):
            datacp[k] = canonicalize(v)

    return datacp


def canonicalize(data: dict) -> str:
    """Convert log to valid JSON types and apply RFC-7159 (Canonical JSON)"""

    if isinstance(data, dict):
        return json.dumps(
            data, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True, default=default_encoder
        )
    elif isinstance(data, datetime.datetime) or isinstance(data, datetime.date):
        return format_datetime(data)
    else:
        return str(data)

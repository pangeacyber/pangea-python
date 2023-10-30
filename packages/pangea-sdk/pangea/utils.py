import base64
import copy
import datetime
import io
import json
from binascii import hexlify
from collections import OrderedDict
from hashlib import new, sha1, sha256, sha512

from google_crc32c import Checksum as CRC32C


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
        return canonicalize(obj)
    else:
        return str(obj)


def str2str_b64(data: str):
    return base64.b64encode(data.encode("ascii")).decode("ascii")


def dict_order_keys(data: dict) -> OrderedDict:
    if isinstance(data, dict):
        return OrderedDict(sorted(data.items()))
    else:
        return data


def dict_order_keys_recursive(data: dict) -> OrderedDict:
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


def hash_sha256(data: str) -> str:
    # Return sha256 hash in hex format
    return hexlify(sha256(data.encode("ascii")).digest()).decode("utf8")


def hash_sha1(data: str) -> str:
    # Return sha1 hash in hex format
    return hexlify(sha1(data.encode("ascii")).digest()).decode("utf8")


def hash_sha512(data: str) -> str:
    # Return sha512 hash in hex format
    return hexlify(sha512(data.encode("ascii")).digest()).decode("utf8")


def hash_ntlm(data: str):
    # Calculate the NTLM hash
    return hexlify(new("md4", data.encode("utf-16le")).digest()).decode("utf8")


def get_prefix(hash: str, len: int = 5):
    return hash[0:len]


def get_presigned_url_upload_params(file: io.BufferedReader):
    if "b" not in file.mode:
        raise AttributeError("File need to be open in binary mode")

    file.seek(0)  # restart reading
    crc = CRC32C()
    size = 0
    sha = sha256()

    while True:
        chunk = file.read(1024 * 1024)
        if not chunk:
            break
        crc.update(chunk)
        sha.update(chunk)
        size += len(chunk)

    file.seek(0)  # restart reading
    return crc.hexdigest().decode("utf-8"), sha.hexdigest(), size, file

import base64
import datetime
from binascii import hexlify
from hashlib import sha1, sha256


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
    else:
        return str(obj)


def str2str_b64(data: str):
    return base64.b64encode(data.encode("ascii")).decode("ascii")


def hash_sha256(data: str) -> str:
    # Return sha256 hash in hex format
    return hexlify(sha256(data.encode("ascii")).digest()).decode("utf8")


def hash_sha1(data: str) -> str:
    # Return sha1 hash in hex format
    return hexlify(sha1(data.encode("ascii")).digest()).decode("utf8")


def get_prefix(hash: str, len: int = 5):
    return hash[0:len]

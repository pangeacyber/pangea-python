import base64
import datetime


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

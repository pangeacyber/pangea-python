import base64
import datetime
import logging
import os


def format_datetime(dt: datetime.datetime) -> str:
    """
    Format a datetime in ISO format, using Z instead of +00:00
    """
    if dt.tzinfo is None:
        dt = dt.astimezone(datetime.timezone.utc)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def setup_logger(path, name, log_level, formatter) -> logging.Logger:
    try:
        os.makedirs(path)
    except FileExistsError:
        pass

    handler = logging.FileHandler(f"{path}{name}.log")
    handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(log_level)
    logger.addHandler(handler)
    return logger


def str2str_b64(data: str):
    return base64.b64encode(data.encode("ascii")).decode("ascii")

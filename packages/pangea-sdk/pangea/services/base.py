# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import logging
from dataclasses import dataclass
from logging.handlers import TimedRotatingFileHandler
from typing import Optional

from pangea import __version__
from pangea.config import PangeaConfig
from pangea.request import PangeaRequest


@dataclass
class LoggerConfig:
    # If set logger, SDK will use this logger without any extra configuration to log
    logger: Optional[logging.Logger] = None

    # If set to True, SDK will user default logger configuration (Ignored if logger is set up)
    logger_enable_default: bool = False

    # Set to choose logger name (if None, service_name is used by default)
    logger_name: Optional[str] = None


class ServiceBase(object):
    service_name: str = "base"
    version: str = "v1"

    def __init__(self, token, config: Optional[PangeaConfig] = None, logger_config: Optional[LoggerConfig] = None):
        if not token:
            raise Exception("No token provided")

        self.config = config if config else PangeaConfig()
        logger = None

        if logger_config:
            if logger_config.logger:
                logger = logger_config.logger
            elif logger_config.logger_enable_default is True or logger_config.logger_name:
                logger = logging.getLogger(
                    logger_config.logger_name if logger_config.logger_name else self.service_name
                )
                handler = TimedRotatingFileHandler(
                    filename="pangea_sdk_logs.json", when="D", interval=1, backupCount=90, encoding="utf-8", delay=False
                )
                formatter = logging.Formatter(
                    fmt="{{'time': '%(asctime)s.%(msecs)03d', 'name': '%(name)s', 'level': '%(levelname)s',  'message': %(message)s }}",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
                handler.setFormatter(formatter)
                logger.addHandler(handler)

        self.request = PangeaRequest(
            self.config,
            token,
            self.version,
            self.service_name,
            logger,
        )

        extra_headers = {}
        self.request.set_extra_headers(extra_headers)

    @property
    def token(self):
        return self.request.token

    @token.setter
    def token(self, value):
        self.request.token = value

    @property
    def logger(self) -> Optional[logging.Logger]:
        return self.request.logger

# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import logging

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.response import PangeaResponse
from pangea.services import Audit
from pangea.services.audit.models import LogResult

SupportedFields = ["actor", "action", "status", "source", "target", "new", "old"]

PANGEA_DOMAIN = ""
PANGEA_AUDIT_TOKEN = ""


class AuditLogger(logging.Logger):
    """Extends Python logger to add the `audit` function to send messages to
    Pangea Audit Service
    """

    def __init__(self, *args, **kwargs):
        super(AuditLogger, self).__init__(*args, **kwargs)

    def set_auditor(self, auditor: Audit):
        """Sets the internal Pangea Audit Service client instance

        Args:
            auditor (pangea.services.Audit) - Audit Service client instance
        """
        self.auditor = auditor

    def audit(self, message, *args, **kwargs):
        """Logs a Pangea Audit message

        Args:
            message (str) - the audit message

            args, kwargs (dict) - key-value args describing an auditable activity.
                See [Audit API Reference](/docs/api/audit)
                for list of required and optional Audit parameters.

        Examples:
            logger.audit("John updated a record in the employees table.")

            logger.audit("Updated a record in the employees table",
                actor="John",
                target="employees table")

            logger.audit("Updated a record in the employees table",
                actor="Jonh",
                target="employess table",
                status="success",
                old= { "status" : "contractor" },
                new= { "status" : "full time" })

        """
        if not self.auditor:
            raise Exception("Audit instance not set")

        audit_record = {
            "message": message,  # required
        }

        for name in SupportedFields:
            if name in kwargs:
                audit_record[name] = kwargs.pop(name)

        try:
            resp: PangeaResponse[LogResult] = self.auditor.log(**audit_record)
            print(f"Response. Hash: {resp.result.hash}")
        except pe.PangeaAPIException as e:
            print(f"Request Error: {e.response.summary}")
            for err in e.errors:
                print(f"\t{err.detail} \n")


def initLogging(domain: str, token: str):
    """Initializes Audit logging environment

    Args:
        domain (string) : the Pangea domain to use, i.e. "aws.us.pangea.cloud"
        token (string) : the Pangea Audit Service token

    Examples:
        import os

        from pangea.audit_logger import AuditLogger, getLogger, initLogging

        PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")
        PANGEA_CSP = os.getenv("PANGEA_CSP")

        initLogging(PANGEA_DOMAIN, PANGEA_TOKEN)
    """
    global PANGEA_DOMAIN, PANGEA_AUDIT_TOKEN

    PANGEA_DOMAIN = domain
    PANGEA_AUDIT_TOKEN = token


def getLogger(name, level=logging.DEBUG) -> AuditLogger:
    """Gets an instance of the AuditLogger

    Args:
        name (str) : name of the logger
        level : debug level

    Examples:
        from pangea.audit_logger import AuditLogger, getLogger

        logger = getLogger(name='myLogger')
        logger.info('This is an info')
        logger.warning('This is a warning')
        logger.error('This is an error')
        logger.audit("hello world")
    """
    audit_config = PangeaConfig(domain=PANGEA_DOMAIN)

    auditor = Audit(token=PANGEA_AUDIT_TOKEN, config=audit_config)
    logging.basicConfig(level=level)
    logging.setLoggerClass(AuditLogger)
    logger: AuditLogger = logging.getLogger(name)
    logger.set_auditor(auditor)

    return logger

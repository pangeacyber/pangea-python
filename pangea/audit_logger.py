# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import logging

from pangea.config import PangeaConfig
from pangea.services import Audit

SupportedFields = ["actor", "action", "status", "source", "target", "new", "old"]

DOMAIN = ""
PANGEA_TOKEN = ""
AUDIT_CONFIG_ID = ""


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
                See [Audit API Reference](https://docs.dev.pangea.cloud/docs/api/audit)
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

        resp = self.auditor.log(audit_record)

        if resp.success:
            pass
        else:
            raise Exception(f"Pangea Audit error: {resp.response.text}")


def initLogging(domain: str, token: str, config_id: str):
    """Initializes Audit logging environment

    Args:
        domain (string) : the Pangea domain to use, i.e. "aws.us.pangea.cloud"
        token (string) : the Pangea Audit Service token
        config_id (string) : the Configuration ID associated with Audit Service profile

    Examples:
        import os

        from pangea.audit_logger import AuditLogger, getLogger, initLogging

        PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")
        AUDIT_CONFIG_ID = os.getenv("AUDIT_CONFIG_ID")
        PANGEA_CSP = os.getenv("PANGEA_CSP")

        initLogging(PANGEA_CSP, PANGEA_TOKEN, AUDIT_CONFIG_ID)
    """
    global DOMAIN, PANGEA_TOKEN, AUDIT_CONFIG_ID

    DOMAIN = domain
    PANGEA_TOKEN = token
    AUDIT_CONFIG_ID = config_id


def getLogger(name, level=logging.DEBUG):
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
    audit_config = PangeaConfig(domain=DOMAIN, config_id=AUDIT_CONFIG_ID)

    auditor = Audit(token=PANGEA_TOKEN, config=audit_config)

    logging.basicConfig(level=level)

    logging.setLoggerClass(AuditLogger)

    logger = logging.getLogger(name)

    logger.set_auditor(auditor)

    return logger

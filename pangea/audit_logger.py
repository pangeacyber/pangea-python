# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import logging

from pangea.services import Audit
from pangea.config import PangeaConfig

SupportedFields = [
    "actor",
    "action",
    "status",
    "source",
    "target",
    "new",
    "old"
]

class AuditLogger(logging.Logger):
    """Extends Python logger to add the `audit` function to send messages to
    Pangea Audit Service
    """
    def __init__(self, *args, **kwargs):
        self.auditor = kwargs.pop('auditor', None)
        super(AuditLogger, self).__init__(*args, **kwargs)

    def set_auditor(self, auditor : Audit):
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
            raise Exception('Audit instance not set')

        audit_record = { 
            'message' : message, # required
        }

        for name in SupportedFields:
            if name in kwargs:
                audit_record[name] = kwargs.pop(name)

        resp = self.auditor.log(audit_record)

        if resp.success:
            pass
        else:
            raise Exception(f'Pangea Audit error: {resp.response.text}')

def getLogger(*args, **kwargs):
    """Gets an instance of the AuditLogger

    Examples:
        import os

        from pangea.audit_logger import AuditLogger, getLogger

        PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")
        AUDIT_CONFIG_ID = os.getenv("AUDIT_CONFIG_ID")
        PANGEA_CSP = os.getenv("PANGEA_CSP")

        logger = getLogger(name='myLogger',
                        csp=PANGEA_CSP,
                        token=PANGEA_TOKEN,
                        config_id=AUDIT_CONFIG_ID)

        assert isinstance(logger, AuditLogger)

        logger.info('This is an info')

        logger.warning('This is a warning')

        logger.error('This is an error')

        logger.audit("hello world")

    """
    name = kwargs.pop('name', 'logger')
    level = kwargs.pop('level', logging.DEBUG)
    csp = kwargs.pop('csp', 'aws')
    token = kwargs.pop('token', '')
    config_id = kwargs.pop('config_id', '')

    audit_config = PangeaConfig(
        base_domain=f'{csp}.pangea.cloud',
        config_id=config_id)

    auditor = Audit(
        token=token,
        config=audit_config)

    logging.basicConfig(level=level)

    logging.setLoggerClass(AuditLogger)

    logger = logging.getLogger(name)

    logger.set_auditor(auditor)

    return logger

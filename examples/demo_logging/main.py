import os

from pangea.audit_logger import AuditLogger, initLogging, getLogger

import module2

PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")
AUDIT_CONFIG_ID = os.getenv("AUDIT_CONFIG_ID")
PANGEA_CSP = os.getenv("PANGEA_CSP")

initLogging(PANGEA_CSP, PANGEA_TOKEN, AUDIT_CONFIG_ID)

logger = getLogger(name=__name__)

assert isinstance(logger, AuditLogger)

logger.info('This is an info')

logger.warning('This is a warning')

logger.error('This is an error')

logger.audit("John updated employees table")

logger.audit("Updated employees table", actor="John", target="employees")

logger.audit("Updated employees table", 
    actor="Jonh", 
    target="employees", 
    status="success",
    old={ "employee status" : "contractor" },
    new={ "employee status" : "full time"})

module2.foo()

import os

import module2

from pangea.audit_logger import AuditLogger, getLogger, initLogging

PANGEA_AUDIT_TOKEN = os.getenv("PANGEA_AUDIT_TOKEN")
DOMAIN = os.getenv("PANGEA_DOMAIN")

initLogging(DOMAIN, PANGEA_AUDIT_TOKEN)

logger = getLogger(name=__name__)

assert isinstance(logger, AuditLogger)

logger.info("This is an info")

logger.warning("This is a warning")

logger.error("This is an error")

logger.audit("John updated employees table")

logger.audit("Updated employees table", actor="John", target="employees")

logger.audit(
    "Updated employees table",
    actor="Jonh",
    target="employees",
    status="success",
    old={"employee status": "contractor"},
    new={"employee status": "full time"},
)

module2.foo()

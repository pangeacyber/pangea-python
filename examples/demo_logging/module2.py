from pangea.audit_logger import AuditLogger, getLogger


def foo():
    logger: AuditLogger = getLogger(name=__name__)

    logger.info("This is foo")
    logger.audit("hello world")

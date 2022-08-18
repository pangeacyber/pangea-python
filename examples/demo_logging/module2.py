from pangea.audit_logger import getLogger


def foo():
    logger = getLogger(name=__name__)

    logger.info("This is foo")
    logger.audit("hello world")

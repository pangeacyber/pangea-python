from pangea.exceptions import PangeaException

from .models import EventEnvelope


# Audit SDK Specific Exceptions
class AuditException(PangeaException):
    """Audit SDK specific exceptions"""


class EventCorruption(AuditException):
    """Event verifications fails"""

    envelope: EventEnvelope

    def __init__(self, message: str, envelope: EventEnvelope):
        super(AuditException, self).__init__(message)
        self.envelope = envelope

from pangea.exceptions import AuditException

from .models import EventEnvelope


class EventCorruption(AuditException):
    """Event verifications fails"""

    envelope: EventEnvelope

    def __init__(self, message: str, envelope: EventEnvelope):
        super(AuditException, self).__init__(message)
        self.envelope = envelope

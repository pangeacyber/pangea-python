from pangea.services import Audit, Redact


class PangeaClient(object):
    def __init__(self, token=""):
        self.default_token = token

        self.__audit = None
        self.__redact = None

    @property
    def audit(self):
        if not self.__audit:
            self.__audit = Audit(token=self.default_token)
        return self.__audit

    @property
    def redact(self):
        if not self.__redact:
            self.__redact = Redact(token=self.default_token)
        return self.__redact

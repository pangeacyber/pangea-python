from pangea.config import PangeaConfig
from pangea.services import Audit, Redact

# FIXME: Should we remove this whole class? Now every services has its own config id. Or if we want to keep it we'll need a huge config struct for each service


class PangeaClient(object):
    """Primary interfacing object that encapsulates supported Pangea Service
    clients.

    Instantiate with a valid PANGEA_TOKEN, see
        [https://docs.dev.pangea.cloud/docs/admin-guide/Services/#tokens](https://docs.dev.pangea.cloud/docs/admin-guide/Services/#tokens).
    """

    def __init__(self, token: str, config: PangeaConfig):
        self.default_token = token

        self.__audit = None
        self.__redact = None
        self.config = config

    @property
    def audit(self):
        if not self.__audit:
            self.__audit = Audit(token=self.default_token, config=self.config)
        return self.__audit

    @property
    def redact(self):
        if not self.__redact:
            self.__redact = Redact(token=self.default_token, config=self.config)
        return self.__redact

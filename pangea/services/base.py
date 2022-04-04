from pangea.request import Request


class ServiceBase(object):
    service_name = "base"
    version = "v1"

    def __init__(self, token=None):
        if not token:
            print("No token provided")
            exit

        self.request = Request(
            token=token, version=self.version, service=self.service_name
        )

    @property
    def token(self):
        return self.request.token

    @token.setter
    def token(self, value):
        self.request.token = value

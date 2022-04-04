from .base import ServiceBase


class Sanitize(ServiceBase):
    service_name = "sanitize"
    version = "v1"

    def sanitize(self, param: str):
        endpoint_name = "sanitize"

        data = {"param": param}

        response = self.request.post(endpoint_name, data=data)

        return response

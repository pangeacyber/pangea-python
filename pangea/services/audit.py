from .base import ServiceBase


class Audit(ServiceBase):
    service_name = "audit"
    version = "v1"

    def log(self, input: dict):
        endpoint_name = "log"

        params = ["action", "actor", "target", "status", "old", "new", "message"]
        data = {}

        for name in params:
            if name in input:
                data[name] = input[name]

        if len(data) < 1:
            # raise exception
            print(
                f"Error: no valid parameters, require on or more of: {', '.join(params)}"
            )
            exit

        response = self.request.post(endpoint_name, data=data)

        return response

    def search(self, query: str):
        endpoint_name = "search"

        data = {
            "query": query,
        }

        response = self.request.post(endpoint_name, data=data)

        return response


class AuditSearchManager(object):
    def __init__(self, token: str = ""):
        self.token = token
        self.actor = None
        self.action = None
        self.target = None
        self.time_filter = None
        self.results = []

        self.audit = Audit(token=token)

    # pass an arbitrary query string
    def query(self, query_string: str):
        response = self.audit.search(query_string)

        return response

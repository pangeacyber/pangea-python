from .base import ServiceBase


class Audit(ServiceBase):
    service_name = "audit"
    version = "v1"

    def log(self, action, actor, target, status, message=None, old=None, new=None):
        endpoint_name = "log"

        data = {
            "action": action,
            "actor": actor,
            "target": target,
            "status": status,
        }

        if message:
            data.update({"message": message})
        if old:
            data.update({"old": old})
        if new:
            data.update({"new": new})

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

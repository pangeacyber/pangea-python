# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation


class JSONObject(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for k, v in self.items():
            k = k.replace(".", "_")
            setattr(self, k, self.compute_attr_value(v))

    def compute_attr_value(self, value):
        if isinstance(value, list):
            return [self.compute_attr_value(x) for x in value]
        elif isinstance(value, dict):
            return JSONObject(value)
        else:
            return value

    def __getattr__(self, item):
        return self[item]


class PangeaResponse(object):
    _json = {}
    _raw = None
    _code = None
    _status = None
    _success = False

    def __init__(self, requests_response):
        self._code = requests_response.status_code
        self._status = requests_response.reason
        self._json = requests_response.json()
        self._success = requests_response.ok
        self._response = requests_response

    @property
    def result(self):
        return self._json.get("result", None)

    @property
    def status(self):
        return self._status

    @property
    def code(self):
        return self._code

    @property
    def success(self):
        return self._success

    @property
    def request_id(self):
        return self._json.get("request_id", None)

    @property
    def response(self):
        return self._response

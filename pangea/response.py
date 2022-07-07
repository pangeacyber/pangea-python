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
        return self.get(item)


class PangeaResponse(object):
    """An object containing Pangea Service API response.

    Properties:
        result (obj): "result" field of the API response as documented at:
            [https://docs.dev.pangea.cloud/docs/api/#responses]
            (https://docs.dev.pangea.cloud/docs/api/#responses)
        status (str): short description message, i.e. "OK"
        code (int): HTTP status code
        success (bool): true if call was successful
        request_id (str): the ID of the request as tracked by Pangea
        response (obj): the entire API response payload

    """

    _data = JSONObject()
    _raw = None
    _code = None
    _status = None
    _success = False

    def __init__(self, requests_response):
        self._code = requests_response.status_code
        self._status = requests_response.reason
        self._data = JSONObject(requests_response.json())
        self._success = requests_response.ok
        self._response = requests_response

    @property
    def result(self):
        return self._data.result

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
        return self._data.get("request_id", None)

    @property
    def response(self):
        return self._response

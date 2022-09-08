# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import typing as t

import requests


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

    def __getattr__(self, name: str):
        return self.get(name)

    def __setattr__(self, name: str, value) -> None:
        self[name] = value


class PangeaResponse(object):
    """An object containing Pangea Service API response.

    Properties:
        result (obj): "result" field of the API response as documented at:
            [https://docs.dev.pangea.cloud/docs/api/#responses](https://docs.dev.pangea.cloud/docs/api/#responses)
        status (str): Pangea status code
        status_code(int): HTTP Status Code
        success (bool): true if call was successful
        request_id (str): the ID of the request as tracked by Pangea
        response (obj): the entire API response payload

    """

    def __init__(self, requests_response: requests.Response):
        data = requests_response.json()
        status = data["status"]
        self._status = status
        self._data = JSONObject(data)
        self._success = status == "Success"
        self._response = requests_response
        self._status_code = requests_response.status_code

    @property
    def result(self) -> t.Optional[dict]:
        return self._data.result

    @property
    def status(self) -> str:
        return self._status

    @property
    def success(self) -> bool:
        return self._success

    @property
    def request_id(self) -> t.Optional[str]:
        return self._data.get("request_id", None)

    @property
    def response(self) -> requests.Response:
        return self._response

    @property
    def code(self) -> int:
        return self._status_code

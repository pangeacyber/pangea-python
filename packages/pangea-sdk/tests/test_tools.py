import os
import unittest

from pangea.exceptions import PangeaException
from pangea.tools import TestEnvironment
from pangea.utils import canonicalize, canonicalize_nested_json, hash_ntlm


def load_test_environment(service_name: str, default: TestEnvironment = TestEnvironment.LIVE) -> TestEnvironment:
    service_name = service_name.replace("-", "_").upper()
    var_name = f"SERVICE_{service_name}_ENV"
    value = os.getenv(var_name)
    if not value:
        print(f"{var_name} is not set. Return default test environment value: {default}")
        return default
    elif value == "DEV":
        return TestEnvironment.DEVELOP
    elif value == "STG":
        return TestEnvironment.STAGING
    elif value == "LVE":
        return TestEnvironment.LIVE
    else:
        raise PangeaException(f"{var_name} not allowed value: {value}")


class TestTools(unittest.TestCase):
    def setUp(self):
        pass

    def test_canonicalize_recursive(self):
        field1 = {"b1": "infob1", "a1": "infoa1"}
        field2 = {"b2": "infob2", "a2": "infoa2"}
        test_data = {"data2": field2, "data1": field1, "data0": "data0"}

        canon = canonicalize(canonicalize_nested_json(test_data))
        print("canonicalize_recursive: ", canon)

    def test_canonicalize(self):
        field1 = {"b1": "infob1", "a1": "infoa1"}
        field2 = {"b2": "infob2", "a2": "infoa2"}
        test_data = {"data2": field2, "data1": field1, "data0": "data0"}

        canon = canonicalize(test_data)
        print("canonicalize: ", canon)

    def test_hash_ntlm(self):
        hash = hash_ntlm("password")
        self.assertEqual(hash, "8846f7eaee8fb117ad06bdd830b7586c")

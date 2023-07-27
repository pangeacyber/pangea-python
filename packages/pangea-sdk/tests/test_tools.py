import unittest

from pangea.utils import canonicalize, canonicalize_nested_json


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

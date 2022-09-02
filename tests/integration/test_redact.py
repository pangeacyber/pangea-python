import os
import unittest

from pangea import PangeaConfig
from pangea.services import Redact


class TestRedact(unittest.TestCase):
    def setUp(self):
        token = os.getenv("PANGEA_TEST_INTEGRATION_TOKEN")
        config_id = os.getenv("REDACT_INTEGRATION_CONFIG_TOKEN")
        domain = os.getenv("PANGEA_TEST_INTEGRATION_ENDPOINT")
        config = PangeaConfig(domain=domain, config_id=config_id)
        self.redact = Redact(token, config=config)

    def test_redact(self):
        data = "Jenny Jenny... 415-867-5309"
        expected = {"redacted_text": "<PERSON>... <PHONE_NUMBER>"}

        response = self.redact.redact(data)
        self.assertEqual(response.code, 200)
        self.assertEqual(response.result, expected)

    def test_redact_structured(self):
        data = {"phone": "415-867-5309"}
        expected = {"redacted_data": {"phone": "<PHONE_NUMBER>"}}

        response = self.redact.redact_structured(data)
        self.assertEqual(response.code, 200)
        self.assertEqual(response.result, expected)

    # call plain redact with structured data, should throw a 400
    def test_redact_with_structured_data(self):
        data = {"phone": "415-867-5309"}

        response = self.redact.redact(data)
        self.assertEqual(response.code, 400)

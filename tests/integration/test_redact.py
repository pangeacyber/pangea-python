import os
import unittest

import pydantic

from pangea import PangeaConfig
from pangea.response import ResponseStatus
from pangea.services import Redact
from pangea.services.redact import RedactInput, StructuredInput


class TestRedact(unittest.TestCase):
    def setUp(self):
        token = os.getenv("PANGEA_TEST_INTEGRATION_TOKEN")
        config_id = os.getenv("REDACT_INTEGRATION_CONFIG_TOKEN")
        domain = os.getenv("PANGEA_TEST_INTEGRATION_ENDPOINT")
        config = PangeaConfig(domain=domain, config_id=config_id)
        self.redact = Redact(token, config=config)

    def test_redact(self):
        text = "Jenny Jenny... 415-867-5309"
        expected = "<PERSON>... <PHONE_NUMBER>"

        response = self.redact.redact(RedactInput(text=text))
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.redacted_text, expected)

    def test_redact_structured(self):
        data = {"phone": "415-867-5309"}
        expected = {"phone": "<PHONE_NUMBER>"}

        response = self.redact.redact_structured(StructuredInput(data=data))
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.redacted_data, expected)

    # call plain redact with structured data, should throw a 400
    def test_redact_with_structured_data(self):
        data = {"phone": "415-867-5309"}

        with self.assertRaises(pydantic.ValidationError):
            self.redact.redact(RedactInput(text=data))  # type: ignore

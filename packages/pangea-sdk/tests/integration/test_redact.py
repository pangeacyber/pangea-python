import unittest

import pangea.exceptions as pe
import pydantic
from pangea import PangeaConfig
from pangea.response import ResponseStatus
from pangea.services import Redact
from pangea.tools import TestEnvironment, get_test_domain, get_test_token, logger_set_pangea_config

TEST_ENVIRONMENT = TestEnvironment.LIVE


class TestRedact(unittest.TestCase):
    def setUp(self):
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test")
        self.redact = Redact(token, config=config, logger_name="pangea")
        logger_set_pangea_config(logger_name=self.redact.logger.name)

    def test_redact(self):
        text = "Jenny Jenny... 415-867-5309"
        expected = "<PERSON>... <PHONE_NUMBER>"

        response = self.redact.redact(text=text)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.redacted_text, expected)
        self.assertEqual(response.result.count, 2)

    def test_redact_no_result(self):
        text = "Jenny Jenny... 415-867-5309"

        response = self.redact.redact(text=text, return_result=False)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNone(response.result.redacted_text)
        self.assertEqual(response.result.count, 2)

    def test_redact_structured(self):
        data = {"phone": "415-867-5309"}
        expected = {"phone": "<PHONE_NUMBER>"}

        response = self.redact.redact_structured(data=data)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.redacted_data, expected)
        self.assertEqual(response.result.count, 1)

    def test_redact_structured_no_result(self):
        data = {"phone": "415-867-5309"}

        response = self.redact.redact_structured(data=data, return_result=False)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNone(response.result.redacted_data)
        self.assertEqual(response.result.count, 1)

    # call plain redact with structured data, should throw a 400
    def test_redact_with_structured_data(self):
        data = {"phone": "415-867-5309"}

        with self.assertRaises(pydantic.ValidationError):
            self.redact.redact(text=data)  # type: ignore

    def test_redact_with_bad_auth_token(self):
        token = "notarealtoken"
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test")
        badredact = Redact(token, config=config)
        text = "Jenny Jenny... 415-867-5309"

        with self.assertRaises(pe.UnauthorizedException):
            badredact.redact(text=text)

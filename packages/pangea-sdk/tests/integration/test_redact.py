import unittest

import pydantic

import pangea.exceptions as pe
from pangea import PangeaConfig
from pangea.response import ResponseStatus
from pangea.services import Redact
from pangea.services.redact import VaultParameters
from pangea.tools import (
    TestEnvironment,
    get_config_id,
    get_multi_config_test_token,
    get_test_domain,
    get_test_token,
    get_vault_fpe_key_id,
    logger_set_pangea_config,
)
from tests.test_tools import load_test_environment

TEST_ENVIRONMENT = load_test_environment(Redact.service_name, TestEnvironment.LIVE)


class TestRedact(unittest.TestCase):
    def setUp(self):
        self.token = get_test_token(TEST_ENVIRONMENT)
        self.domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=self.domain, custom_user_agent="sdk-test")
        self.redact = Redact(self.token, config=config, logger_name="pangea")
        self.multi_config_token = get_multi_config_test_token(TEST_ENVIRONMENT)
        logger_set_pangea_config(logger_name=self.redact.logger.name)
        self.vault_fpe_key_id = get_vault_fpe_key_id(TEST_ENVIRONMENT)

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

    def test_redact_structured_no_result(self) -> None:
        data = {"phone": "415-867-5309"}

        response = self.redact.redact_structured(data=data, return_result=False)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNone(response.result.redacted_data)
        self.assertEqual(response.result.count, 1)

    # call plain redact with structured data, should throw a 400
    def test_redact_with_structured_data(self) -> None:
        data = {"phone": "415-867-5309"}

        with self.assertRaises(pydantic.ValidationError):
            self.redact.redact(text=data)

    def test_redact_with_bad_auth_token(self) -> None:
        token = "notarealtoken"
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test")
        badredact = Redact(token, config=config)
        text = "Jenny Jenny... 415-867-5309"

        with self.assertRaises(pe.UnauthorizedException):
            badredact.redact(text=text)

    def test_multi_config_redact(self):
        config = PangeaConfig(domain=self.domain)
        redact_multi_config = Redact(self.multi_config_token, config=config)

        def redact_without_config_id():
            text = "Jenny Jenny... 415-867-5309"
            response = redact_multi_config.redact(text=text)
            print(response.result)

        # This should fail because this token has multi config but we didn't set up a config id
        self.assertRaises(pe.PangeaAPIException, redact_without_config_id)

    def test_multi_config_redact_config_1(self):
        config_id = get_config_id(TEST_ENVIRONMENT, "redact", 1)
        config = PangeaConfig(domain=self.domain)
        redact_multi_config = Redact(self.multi_config_token, config=config, config_id=config_id)

        text = "Jenny Jenny... 415-867-5309"
        expected = "<PERSON>... <PHONE_NUMBER>"

        response = redact_multi_config.redact(text=text)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.redacted_text, expected)
        self.assertEqual(response.result.count, 2)

    def test_multi_config_redact_config_2(self):
        config_id = get_config_id(TEST_ENVIRONMENT, "redact", 2)
        config = PangeaConfig(domain=self.domain)
        redact_multi_config = Redact(self.multi_config_token, config=config, config_id=config_id)

        text = "Jenny Jenny... 415-867-5309"
        expected = "<PERSON>... <PHONE_NUMBER>"

        response = redact_multi_config.redact(text=text)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.redacted_text, expected)
        self.assertEqual(response.result.count, 2)

    def test_unredact(self):
        text = "Visit our web is https://pangea.cloud"
        redact_response = self.redact.redact(
            text=text, vault_parameters=VaultParameters(fpe_key_id=self.vault_fpe_key_id)
        )
        self.assertIsNotNone(redact_response.result)
        self.assertIsNotNone(redact_response.result.redacted_text)
        self.assertIsNotNone(redact_response.result.fpe_context)
        self.assertIsNot(redact_response.result.redacted_text, text)

        unredact_response = self.redact.unredact(
            redacted_data=redact_response.result.redacted_text, fpe_context=redact_response.result.fpe_context
        )
        self.assertIsNotNone(unredact_response.result)
        self.assertIsNotNone(unredact_response.result.data)
        self.assertEqual(unredact_response.result.data, text)

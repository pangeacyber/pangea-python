import unittest

import pangea.exceptions as pe
from pangea import PangeaConfig
from pangea.services import Embargo
from pangea.tools import TestEnvironment, get_test_domain, get_test_token, logger_set_pangea_config

TEST_ENVIRONMENT = TestEnvironment.LIVE


class TestEmbargo(unittest.TestCase):
    def setUp(self):
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test")
        self.embargo = Embargo(token, config=config)
        logger_set_pangea_config(logger_name=self.embargo.logger.name)

    def test_ip_check(self):
        response = self.embargo.ip_check(ip="213.24.238.26")
        self.assertEqual(response.status, "Success")
        self.assertGreaterEqual(len(response.result.sanctions), 1)

        sanction = response.result.sanctions[0]
        self.assertEqual(sanction.list_name, "US - ITAR")
        self.assertEqual(sanction.embargoed_country_name, "Russia")
        self.assertEqual(sanction.embargoed_country_iso_code, "RU")
        self.assertEqual(sanction.issuing_country, "US")

    def test_iso_check(self):
        response = self.embargo.iso_check(iso_code="CU")

        self.assertEqual(response.status, "Success")
        self.assertGreaterEqual(len(response.result.sanctions), 1)

        sanction = response.result.sanctions[0]
        self.assertEqual(sanction.list_name, "US - ITAR")
        self.assertEqual(sanction.embargoed_country_name, "Cuba")
        self.assertEqual(sanction.embargoed_country_iso_code, "CU")
        self.assertEqual(sanction.issuing_country, "US")

    def test_embargo_with_bad_auth_token(self):
        token = "noarealauthtoken"
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain)
        badembargo = Embargo(token, config=config)

        with self.assertRaises(pe.UnauthorizedException):
            badembargo.ip_check(ip="213.24.238.26")

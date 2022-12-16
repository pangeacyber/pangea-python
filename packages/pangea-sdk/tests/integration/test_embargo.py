import unittest

import pangea.exceptions as pe
from pangea import PangeaConfig
from pangea.services import Embargo
from pangea.tools_util import TestEnvironment, get_test_domain, get_test_token

TEST_ENVIRONMENT = TestEnvironment.PRODUCTION


class TestEmbargo(unittest.TestCase):
    def setUp(self):
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain)
        self.embargo = Embargo(token, config=config)

    def test_ip_check(self):
        response = self.embargo.ip_check(ip="213.24.238.26")
        self.assertEqual(response.status, "Success")
        self.assertGreaterEqual(len(response.result.sanctions), 1)

        sanction = response.result.sanctions[0]
        self.assertEqual(sanction.list_name, "ITAR")
        self.assertEqual(sanction.embargoed_country_name, "Russia")
        self.assertEqual(sanction.embargoed_country_iso_code, "RU")
        self.assertEqual(sanction.issuing_country, "US")

    def test_iso_check(self):
        response = self.embargo.iso_check(iso_code="CU")

        self.assertEqual(response.status, "Success")
        self.assertGreaterEqual(len(response.result.sanctions), 1)

        sanction = response.result.sanctions[0]
        self.assertEqual(sanction.list_name, "ITAR")
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

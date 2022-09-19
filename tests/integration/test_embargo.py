import os
import unittest

from schema import And, Schema

from pangea import PangeaConfig
from pangea.services import Embargo
from pangea.services.embargo import IPCheckInput, ISOCheckInput


class TestEmbargo(unittest.TestCase):
    def setUp(self):
        token = os.getenv("PANGEA_TEST_INTEGRATION_TOKEN")
        config_id = os.getenv("EMBARGO_INTEGRATION_CONFIG_TOKEN")
        domain = os.getenv("PANGEA_TEST_INTEGRATION_ENDPOINT")
        config = PangeaConfig(domain=domain, config_id=config_id)
        self.embargo = Embargo(token, config=config)

    def test_ip_check(self):
        response = self.embargo.ip_check(IPCheckInput(ip="213.24.238.26"))
        self.assertEqual(response.status, "Success")
        self.assertGreaterEqual(len(response.result.sanctions), 1)

        sanction = response.result.sanctions[0]
        self.assertEqual(sanction.list_name, "ITAR")
        self.assertEqual(sanction.embargoed_country_name, "Russia")
        self.assertEqual(sanction.embargoed_country_iso_code, "RU")
        self.assertEqual(sanction.issuing_country, "US")

    def test_iso_check(self):
        response = self.embargo.iso_check(ISOCheckInput(iso_code="CU"))

        self.assertEqual(response.status, "Success")
        self.assertGreaterEqual(len(response.result.sanctions), 1)

        sanction = response.result.sanctions[0]
        self.assertEqual(sanction.list_name, "ITAR")
        self.assertEqual(sanction.embargoed_country_name, "Cuba")
        self.assertEqual(sanction.embargoed_country_iso_code, "CU")
        self.assertEqual(sanction.issuing_country, "US")

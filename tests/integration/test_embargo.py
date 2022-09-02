import os
import unittest

from schema import And, Schema

from pangea import PangeaConfig
from pangea.services import Embargo


class TestEmbargo(unittest.TestCase):
    def setUp(self):
        token = os.getenv("PANGEA_TEST_INTEGRATION_TOKEN")
        config_id = os.getenv("EMBARGO_INTEGRATION_CONFIG_TOKEN")
        domain = os.getenv("PANGEA_TEST_INTEGRATION_ENDPOINT")
        config = PangeaConfig(domain=domain, config_id=config_id)
        self.embargo = Embargo(token, config=config)

    def test_ip_check(self):
        schema = Schema(
            {
                "list_name": "ITAR",
                "embargoed_country_name": "Russia",
                "embargoed_country_iso_code": "RU",
                "issuing_country": "US",
                "annotations": dict,
            }
        )

        response = self.embargo.ip_check("213.24.238.26")
        self.assertEqual(response.code, 200)

        sanction = response.result.sanctions[0]
        self.assertTrue(schema.is_valid(sanction))

    def test_iso_check(self):
        schema = Schema(
            {
                "list_name": "ITAR",
                "embargoed_country_name": "Cuba",
                "embargoed_country_iso_code": "CU",
                "issuing_country": "US",
                "annotations": dict,
            }
        )

        response = self.embargo.iso_check("CU")
        self.assertEqual(response.code, 200)

        sanction = response.result.sanctions[0]
        self.assertTrue(schema.is_valid(sanction))

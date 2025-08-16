from __future__ import annotations

import unittest

import pangea.exceptions as pe
from pangea import PangeaConfig
from pangea.asyncio.services import EmbargoAsync
from pangea.tools import TestEnvironment, get_test_domain, get_test_token, logger_set_pangea_config
from tests.test_tools import load_test_environment

TEST_ENVIRONMENT = load_test_environment(EmbargoAsync.service_name, TestEnvironment.LIVE)


class TestEmbargo(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test")
        self.embargo = EmbargoAsync(token, config=config)
        logger_set_pangea_config(logger_name=self.embargo.logger.name)

    async def asyncTearDown(self):
        await self.embargo.close()

    async def test_ip_check(self):
        response = await self.embargo.ip_check(ip="213.24.238.26")
        self.assertEqual(response.status, "Success")
        self.assertGreaterEqual(len(response.result.sanctions), 1)

        sanction = response.result.sanctions[0]
        self.assertEqual(sanction.list_name, "US - ITAR")
        self.assertEqual(sanction.embargoed_country_name, "Russia")
        self.assertEqual(sanction.embargoed_country_iso_code, "RU")
        self.assertEqual(sanction.issuing_country, "US")

    async def test_iso_check(self):
        response = await self.embargo.iso_check(iso_code="CU")

        self.assertEqual(response.status, "Success")
        self.assertGreaterEqual(len(response.result.sanctions), 1)

        sanction = response.result.sanctions[0]
        self.assertEqual(sanction.list_name, "US - ITAR")
        self.assertEqual(sanction.embargoed_country_name, "Cuba")
        self.assertEqual(sanction.embargoed_country_iso_code, "CU")
        self.assertEqual(sanction.issuing_country, "US")

    async def test_embargo_with_bad_auth_token(self):
        token = "noarealauthtoken"
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain)
        async with EmbargoAsync(token, config=config) as badembargo:
            with self.assertRaises(pe.UnauthorizedException):
                await badembargo.ip_check(ip="213.24.238.26")

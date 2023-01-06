import unittest

import pangea.exceptions as pe
from pangea import PangeaConfig
from pangea.response import ResponseStatus
from pangea.services import DomainIntel, FileIntel, IpIntel, UrlIntel
from pangea.tools_util import TestEnvironment, get_test_domain, get_test_token

TEST_ENVIRONMENT = TestEnvironment.LIVE

# FIXME: Remove this before push to prod. It's used to test geolocate now
TEST_DEVELOP = TestEnvironment.DEVELOP


class TestDomainIntel(unittest.TestCase):
    def setUp(self):
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain)
        self.intel_domain = DomainIntel(token, config=config)

    def test_domain_lookup(self):
        response = self.intel_domain.lookup(
            domain="737updatesboeing.com", provider="domaintools", verbose=True, raw=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.verdict, "malicious")

    def test_domain_lookup_with_bad_auth_token(self):
        token = "noarealtoken"
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain)
        badintel_domain = DomainIntel(token, config=config)

        with self.assertRaises(pe.UnauthorizedException):
            badintel_domain.lookup(domain="737updatesboeing.com", provider="domaintools")


class TestFileIntel(unittest.TestCase):
    def setUp(self):
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain)
        self.intel_file = FileIntel(token, config=config)

    def test_file_lookup(self):
        response = self.intel_file.lookup(
            hash="142b638c6a60b60c7f9928da4fb85a5a8e1422a9ffdc9ee49e17e56ccca9cf6e",
            hash_type="sha256",
            provider="reversinglabs",
            verbose=True,
            raw=True,
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.verdict, "malicious")

    def test_file_lookup_default_provider(self):
        response = self.intel_file.lookup(
            hash="142b638c6a60b60c7f9928da4fb85a5a8e1422a9ffdc9ee49e17e56ccca9cf6e",
            hash_type="sha256",
            verbose=True,
            raw=True,
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)

    def test_file_lookup_from_filepath(self):
        response = self.intel_file.lookupFilepath(
            filepath="./README.md",
            provider="reversinglabs",
            verbose=True,
            raw=True,
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.verdict, "unknown")

    def test_file_lookup_with_bad_auth_token(self):
        token = "noarealtoken"
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain)
        badintel_domain = FileIntel(token, config=config)

        with self.assertRaises(pe.UnauthorizedException):
            badintel_domain.lookup(
                hash="142b638c6a60b60c7f9928da4fb85a5a8e1422a9ffdc9ee49e17e56ccca9cf6e",
                hash_type="sha256",
                provider="reversinglabs",
            )

    def test_file_lookup_with_bad_hash(self):
        with self.assertRaises(pe.PangeaAPIException):
            self.intel_file.lookup(hash="notarealhash", hash_type="sha256", provider="reversinglabs")

    def test_file_lookup_with_no_provider(self):
        with self.assertRaises(pe.PangeaAPIException):
            self.intel_file.lookup(
                hash="142b638c6a60b60c7f9928da4fb85a5a8e1422a9ffdc9ee49e17e56ccca9cf6e",
                hash_type="notavalidhashtype",
                provider="reversinglabs",
            )


class TestIPIntel(unittest.TestCase):
    def setUp(self):
        token = get_test_token(TEST_DEVELOP)
        domain = get_test_domain(TEST_DEVELOP)
        config = PangeaConfig(domain=domain)
        self.intel_ip = IpIntel(token, config=config)

    def test_ip_lookup(self):
        response = self.intel_ip.lookup(ip="93.231.182.110", provider="crowdstrike", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.verdict, "malicious")

    def test_ip_lookup_default_provider(self):
        response = self.intel_ip.lookup(ip="93.231.182.110", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)

    def test_ip_geolocate(self):
        response = self.intel_ip.geolocate(ip="93.231.182.110", provider="digitalenvoy", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.country, "deu")
        self.assertEqual(response.result.data.city, "unna")
        self.assertEqual(response.result.data.postal_code, "59425")

    def test_ip_geolocate_default_provider(self):
        response = self.intel_ip.geolocate(ip="93.231.182.110", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.country, "deu")
        self.assertEqual(response.result.data.city, "unna")
        self.assertEqual(response.result.data.postal_code, "59425")

    def test_ip_lookup_with_bad_auth_token(self):
        token = "noarealtoken"
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain)
        badintel_ip = IpIntel(token, config=config)

        with self.assertRaises(pe.UnauthorizedException):
            badintel_ip.lookup(ip="93.231.182.110", provider="crowdstrike")


class TestURLIntel(unittest.TestCase):
    def setUp(self):
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain)
        self.intel_url = UrlIntel(token, config=config)

    def test_url_lookup(self):
        response = self.intel_url.lookup(
            url="http://113.235.101.11:54384", provider="crowdstrike", verbose=True, raw=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.verdict, "malicious")

    def test_url_lookup_default_provider(self):
        response = self.intel_url.lookup(url="http://113.235.101.11:54384", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)

    def test_url_lookup_with_bad_auth_token(self):
        token = "noarealtoken"
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain)
        badintel_url = UrlIntel(token, config=config)

        with self.assertRaises(pe.UnauthorizedException):
            badintel_url.lookup(url="http://113.235.101.11:54384", provider="crowdstrike")

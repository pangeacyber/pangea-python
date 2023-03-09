import unittest

import pangea.exceptions as pe
from pangea import PangeaConfig
from pangea.response import ResponseStatus
from pangea.services import DomainIntel, FileIntel, IpIntel, UrlIntel
from pangea.tools import TestEnvironment, get_test_domain, get_test_token, logger_set_pangea_config

TEST_ENVIRONMENT = TestEnvironment.LIVE


class TestDomainIntel(unittest.TestCase):
    def setUp(self):
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain)
        self.intel_domain = DomainIntel(token, config=config, logger_name="pangea")
        logger_set_pangea_config(logger_name=self.intel_domain.logger.name)

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

    def test_domain_reputation(self):
        response = self.intel_domain.reputation(
            domain="737updatesboeing.com", provider="domaintools", verbose=True, raw=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.verdict, "malicious")

    def test_domain_reputation_with_bad_auth_token(self):
        token = "noarealtoken"
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain)
        badintel_domain = DomainIntel(token, config=config)

        with self.assertRaises(pe.UnauthorizedException):
            badintel_domain.reputation(domain="737updatesboeing.com", provider="domaintools")


class TestFileIntel(unittest.TestCase):
    def setUp(self):
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain)
        self.intel_file = FileIntel(token, config=config, logger_name="pangea")
        logger_set_pangea_config(logger_name=self.intel_file.logger.name)

    def test_file_lookup(self):
        response = self.intel_file.lookup(
            hash="142b638c6a60b60c7f9928da4fb85a5a8e1422a9ffdc9ee49e17e56ccca9cf6e",
            hash_type="sha256",
            provider="reversinglabs",
            verbose=True,
            raw=True,
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.verdict, "unknown")

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
        badintel_domain = FileIntel(token, config=config, logger_name="pangea")
        logger_set_pangea_config(logger_name=self.intel_file.logger.name)

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

    def test_file_reputation(self):
        response = self.intel_file.hashReputation(
            hash="142b638c6a60b60c7f9928da4fb85a5a8e1422a9ffdc9ee49e17e56ccca9cf6e",
            hash_type="sha256",
            provider="reversinglabs",
            verbose=True,
            raw=True,
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.verdict, "unknown")

    def test_file_reputation_default_provider(self):
        response = self.intel_file.hashReputation(
            hash="142b638c6a60b60c7f9928da4fb85a5a8e1422a9ffdc9ee49e17e56ccca9cf6e",
            hash_type="sha256",
            verbose=True,
            raw=True,
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)

    def test_file_reputation_from_filepath(self):
        response = self.intel_file.filepathReputation(
            filepath="./README.md",
            provider="reversinglabs",
            verbose=True,
            raw=True,
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.verdict, "unknown")

    def test_file_reputation_with_bad_auth_token(self):
        token = "noarealtoken"
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain)
        badintel_domain = FileIntel(token, config=config)

        with self.assertRaises(pe.UnauthorizedException):
            badintel_domain.hashReputation(
                hash="142b638c6a60b60c7f9928da4fb85a5a8e1422a9ffdc9ee49e17e56ccca9cf6e",
                hash_type="sha256",
                provider="reversinglabs",
            )

    def test_file_reputation_with_bad_hash(self):
        with self.assertRaises(pe.PangeaAPIException):
            self.intel_file.hashReputation(hash="notarealhash", hash_type="sha256", provider="reversinglabs")

    def test_file_reputation_with_no_provider(self):
        with self.assertRaises(pe.PangeaAPIException):
            self.intel_file.hashReputation(
                hash="142b638c6a60b60c7f9928da4fb85a5a8e1422a9ffdc9ee49e17e56ccca9cf6e",
                hash_type="notavalidhashtype",
                provider="reversinglabs",
            )


class TestIPIntel(unittest.TestCase):
    def setUp(self):
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain)
        self.intel_ip = IpIntel(token, config=config, logger_name="pangea")
        logger_set_pangea_config(logger_name=self.intel_ip.logger.name)

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
        self.assertEqual(response.result.data.country, "Federal Republic Of Germany")
        self.assertEqual(response.result.data.city, "unna")
        self.assertEqual(response.result.data.postal_code, "59425")

    def test_ip_geolocate_default_provider(self):
        response = self.intel_ip.geolocate(ip="93.231.182.110", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.country, "Federal Republic Of Germany")
        self.assertEqual(response.result.data.city, "unna")
        self.assertEqual(response.result.data.postal_code, "59425")

    def test_ip_domain(self):
        response = self.intel_ip.get_domain(ip="24.235.114.61", provider="digitalenvoy", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.domain_found)
        self.assertEqual("rogers.com", response.result.data.domain)

    def test_ip_domain_default_provider(self):
        response = self.intel_ip.get_domain(ip="24.235.114.61", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.domain_found)
        self.assertEqual("rogers.com", response.result.data.domain)

    def test_ip_vpn(self):
        response = self.intel_ip.is_vpn(ip="2.56.189.74", provider="digitalenvoy", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.is_vpn)

    def test_ip_vpn_default_provider(self):
        response = self.intel_ip.is_vpn(ip="2.56.189.74", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.is_vpn)

    def test_ip_proxy(self):
        response = self.intel_ip.is_proxy(ip="1.0.136.28", provider="digitalenvoy", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.is_proxy)

    def test_ip_proxy_default_provider(self):
        response = self.intel_ip.is_proxy(ip="1.0.136.28", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.is_proxy)

    def test_ip_lookup_with_bad_auth_token(self):
        token = "noarealtoken"
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain)
        badintel_ip = IpIntel(token, config=config)

        with self.assertRaises(pe.UnauthorizedException):
            badintel_ip.lookup(ip="93.231.182.110", provider="crowdstrike")

    def test_ip_reputation(self):
        response = self.intel_ip.reputation(ip="93.231.182.110", provider="crowdstrike", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.verdict, "malicious")

    def test_ip_reputation_default_provider(self):
        response = self.intel_ip.reputation(ip="93.231.182.110", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)

    def test_ip_reputation_with_bad_auth_token(self):
        token = "noarealtoken"
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain)
        badintel_ip = IpIntel(token, config=config)

        with self.assertRaises(pe.UnauthorizedException):
            badintel_ip.reputation(ip="93.231.182.110", provider="crowdstrike")


class TestURLIntel(unittest.TestCase):
    def setUp(self):
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain)
        self.intel_url = UrlIntel(token, config=config, logger_name="pangea")
        logger_set_pangea_config(logger_name=self.intel_url.logger.name)

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

    def test_url_reputation(self):
        response = self.intel_url.reputation(
            url="http://113.235.101.11:54384", provider="crowdstrike", verbose=True, raw=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.verdict, "malicious")

    def test_url_reputation_default_provider(self):
        response = self.intel_url.reputation(url="http://113.235.101.11:54384", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)

    def test_url_reputation_with_bad_auth_token(self):
        token = "noarealtoken"
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain)
        badintel_url = UrlIntel(token, config=config)

        with self.assertRaises(pe.UnauthorizedException):
            badintel_url.reputation(url="http://113.235.101.11:54384", provider="crowdstrike")

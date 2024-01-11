import unittest
from typing import Dict

import pangea.exceptions as pe
from pangea import PangeaConfig
from pangea.response import ResponseStatus
from pangea.services import DomainIntel, FileIntel, IpIntel, UrlIntel, UserIntel
from pangea.services.intel import HashType, IntelReputationData
from pangea.tools import TestEnvironment, get_test_domain, get_test_token, logger_set_pangea_config

TEST_ENVIRONMENT = TestEnvironment.LIVE


def check_bulk_data(self: unittest.TestCase, data: Dict[str, IntelReputationData]):
    for item in data.values():
        self.assertIsNotNone(item.verdict)
        self.assertNotEqual("", item.verdict)
        self.assertIsNotNone(item.category)
        self.assertNotEqual([], item.category)
        self.assertIsNotNone(item.score)
        self.assertNotEqual(0, item.score)


class TestDomainIntel(unittest.TestCase):
    def setUp(self):
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test")
        self.intel_domain = DomainIntel(token, config=config, logger_name="pangea")
        logger_set_pangea_config(logger_name=self.intel_domain.logger.name)

    def test_domain_reputation(self):
        response = self.intel_domain.reputation(
            domain="737updatesboeing.com", provider="crowdstrike", verbose=True, raw=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.verdict, "malicious")

    def test_domain_reputation_bulk(self):
        domain_list = ["pemewizubidob.cafij.co.za", "redbomb.com.tr", "kmbk8.hicp.net"]
        response = self.intel_domain.reputation_bulk(
            domains=domain_list, provider="crowdstrike", verbose=True, raw=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response.result.data), 3)

    def test_domain_who_is(self):
        response = self.intel_domain.who_is(domain="737updatesboeing.com", provider="whoisxml", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.data)
        self.assertIsNotNone(response.result.data.domain_name)
        self.assertIsNotNone(response.result.data.domain_availability)

    def test_domain_who_is_default_provider(self):
        response = self.intel_domain.who_is(domain="737updatesboeing.com", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.data)
        self.assertIsNotNone(response.result.data.domain_name)
        self.assertIsNotNone(response.result.data.domain_availability)

    def test_domain_reputation_not_found(self):
        response = self.intel_domain.reputation(
            domain="thisshouldbeafakedomain12312asdasd.com", provider="crowdstrike", verbose=True, raw=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.data)
        self.assertIsNotNone(response.result.data.category)
        self.assertIsNotNone(response.result.data.verdict)
        self.assertIsNotNone(response.result.data.score)

    def test_domain_reputation_with_bad_auth_token(self):
        token = "noarealtoken"
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test")
        badintel_domain = DomainIntel(token, config=config)

        with self.assertRaises(pe.UnauthorizedException):
            badintel_domain.reputation(domain="737updatesboeing.com", provider="domaintools")


class TestFileIntel(unittest.TestCase):
    def setUp(self):
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test")
        self.intel_file = FileIntel(token, config=config, logger_name="pangea")
        logger_set_pangea_config(logger_name=self.intel_file.logger.name)

    def test_file_reputation(self):
        response = self.intel_file.hash_reputation(
            hash="142b638c6a60b60c7f9928da4fb85a5a8e1422a9ffdc9ee49e17e56ccca9cf6e",
            hash_type="sha256",
            provider="reversinglabs",
            verbose=True,
            raw=True,
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.verdict, "malicious")

    def test_file_reputation_bulk(self):
        hash_list = [
            "142b638c6a60b60c7f9928da4fb85a5a8e1422a9ffdc9ee49e17e56ccca9cf6e",
            "179e2b8a4162372cd9344b81793cbf74a9513a002eda3324e6331243f3137a63",
        ]
        response = self.intel_file.hash_reputation_bulk(
            hashes=hash_list,
            hash_type="sha256",
            provider="reversinglabs",
            verbose=True,
            raw=True,
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response.result.data), 2)
        check_bulk_data(self, response.result.data)

    def test_file_reputation_default_provider(self):
        response = self.intel_file.hash_reputation(
            hash="142b638c6a60b60c7f9928da4fb85a5a8e1422a9ffdc9ee49e17e56ccca9cf6e",
            hash_type="sha256",
            verbose=True,
            raw=True,
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)

    def test_file_reputation_from_filepath(self):
        response = self.intel_file.filepath_reputation(
            filepath="./README.md",
            provider="reversinglabs",
            verbose=True,
            raw=True,
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)

    def test_file_reputation_from_filepath_bulk(self):
        response = self.intel_file.filepath_reputation_bulk(
            filepaths=["./README.md", "./CONTRIBUTING.md"],
            provider="reversinglabs",
            verbose=True,
            raw=True,
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response.result.data), 2)

    def test_file_reputation_with_bad_auth_token(self):
        token = "noarealtoken"
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test")
        badintel_domain = FileIntel(token, config=config)

        with self.assertRaises(pe.UnauthorizedException):
            badintel_domain.hash_reputation(
                hash="142b638c6a60b60c7f9928da4fb85a5a8e1422a9ffdc9ee49e17e56ccca9cf6e",
                hash_type="sha256",
                provider="reversinglabs",
            )

    def test_file_reputation_with_bad_hash(self):
        with self.assertRaises(pe.PangeaAPIException):
            self.intel_file.hash_reputation(hash="notarealhash", hash_type="sha256", provider="reversinglabs")

    def test_file_reputation_with_no_provider(self):
        with self.assertRaises(pe.PangeaAPIException):
            self.intel_file.hash_reputation(
                hash="142b638c6a60b60c7f9928da4fb85a5a8e1422a9ffdc9ee49e17e56ccca9cf6e",
                hash_type="notavalidhashtype",
                provider="reversinglabs",
            )


class TestIPIntel(unittest.TestCase):
    def setUp(self):
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test")
        self.intel_ip = IpIntel(token, config=config, logger_name="pangea")
        logger_set_pangea_config(logger_name=self.intel_ip.logger.name)

    def test_ip_geolocate_default_provider(self):
        response = self.intel_ip.geolocate(ip="93.231.182.110", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.country, "Federal Republic Of Germany")
        self.assertIsNotNone(response.result.data.city)
        self.assertEqual(len(response.result.data.postal_code), 5)

    def test_ip_geolocate_default_provider_bulk(self):
        response = self.intel_ip.geolocate_bulk(ips=["93.231.182.110", "24.235.114.61"], verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response.result.data), 2)

    def test_ip_domain(self):
        response = self.intel_ip.get_domain(ip="24.235.114.61", provider="digitalelement", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.domain_found)
        self.assertEqual("rogers.com", response.result.data.domain)

    def test_ip_domain_bulk(self):
        response = self.intel_ip.get_domain_bulk(
            ips=["24.235.114.61", "93.231.182.110"], provider="digitalelement", verbose=True, raw=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response.result.data), 2)

    def test_ip_domain_default_provider(self):
        response = self.intel_ip.get_domain(ip="24.235.114.61", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.domain_found)
        self.assertEqual("rogers.com", response.result.data.domain)

    def test_ip_domain_not_found(self):
        response = self.intel_ip.get_domain(ip="127.0.0.1", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.data)
        self.assertIsNotNone(response.result.parameters)
        self.assertFalse(response.result.data.domain_found)
        self.assertIsNone(response.result.data.domain)

    def test_ip_vpn(self):
        response = self.intel_ip.is_vpn(ip="2.56.189.74", provider="digitalelement", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.is_vpn)

    def test_ip_vpn_bulk(self):
        response = self.intel_ip.is_vpn_bulk(
            ips=["2.56.189.74", "24.235.114.61"], provider="digitalelement", verbose=True, raw=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response.result.data), 2)

    def test_ip_vpn_default_provider(self):
        response = self.intel_ip.is_vpn(ip="2.56.189.74", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.is_vpn)

    def test_ip_vpn_not_found(self):
        response = self.intel_ip.is_vpn(ip="127.0.0.1", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.data)
        self.assertFalse(response.result.data.is_vpn)

    def test_ip_proxy(self):
        response = self.intel_ip.is_proxy(ip="34.201.32.172", provider="digitalelement", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.is_proxy)

    def test_ip_proxy_bulk(self):
        response = self.intel_ip.is_proxy_bulk(
            ips=["34.201.32.172", "2.56.189.74"], provider="digitalelement", verbose=True, raw=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response.result.data), 2)

    def test_ip_proxy_default_provider(self):
        response = self.intel_ip.is_proxy(ip="34.201.32.172", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.is_proxy)

    def test_ip_proxy_not_found(self):
        response = self.intel_ip.is_proxy(ip="127.0.0.1", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.data)
        self.assertFalse(response.result.data.is_proxy)

    def test_ip_reputation_crowdstrike(self):
        response = self.intel_ip.reputation(ip="93.231.182.110", provider="crowdstrike", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.verdict, "malicious")

    def test_ip_reputation_cymru(self):
        response = self.intel_ip.reputation(ip="93.231.182.110", provider="cymru", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)

    def test_ip_reputation_crowdstrike_not_found(self):
        response = self.intel_ip.reputation(ip="127.0.0.1", provider="crowdstrike", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.data)
        self.assertIsNotNone(response.result.data.category)
        self.assertIsNotNone(response.result.data.verdict)
        self.assertIsNotNone(response.result.data.score)

    def test_ip_reputation_cymru_not_found(self):
        response = self.intel_ip.reputation(ip="127.0.0.1", provider="cymru", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.data)
        self.assertIsNotNone(response.result.data.category)
        self.assertIsNotNone(response.result.data.verdict)
        self.assertIsNotNone(response.result.data.score)

    def test_ip_reputation_default_provider(self):
        response = self.intel_ip.reputation(ip="93.231.182.110", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)

    def test_ip_reputation_bulk(self):
        ip_list = ["93.231.182.110", "190.28.74.251"]
        response = self.intel_ip.reputation_bulk(ips=ip_list, provider="crowdstrike", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response.result.data), 2)
        check_bulk_data(self, response.result.data)

    def test_ip_reputation_with_bad_auth_token(self):
        token = "noarealtoken"
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test")
        badintel_ip = IpIntel(token, config=config)

        with self.assertRaises(pe.UnauthorizedException):
            badintel_ip.reputation(ip="93.231.182.110", provider="crowdstrike")


class TestURLIntel(unittest.TestCase):
    def setUp(self):
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test")
        self.intel_url = UrlIntel(token, config=config, logger_name="pangea")
        logger_set_pangea_config(logger_name=self.intel_url.logger.name)

    def test_url_reputation(self):
        response = self.intel_url.reputation(
            url="http://113.235.101.11:54384", provider="crowdstrike", verbose=True, raw=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.verdict, "malicious")

    def test_url_reputation_bulk(self):
        url_list = [
            "http://113.235.101.11:54384",
            "http://45.14.49.109:54819",
            "https://chcial.ru/uplcv?utm_term%3Dcost%2Bto%2Brezone%2Bland",
        ]
        response = self.intel_url.reputation_bulk(urls=url_list, provider="crowdstrike", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response.result.data), 3)
        check_bulk_data(self, response.result.data)

    def test_url_reputation_default_provider(self):
        response = self.intel_url.reputation(url="http://113.235.101.11:54384", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)

    def test_url_reputation_default_provider_not_found(self):
        response = self.intel_url.reputation(url="http://thisshoulbeafakseurl123123lkj:54384", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.data)
        self.assertIsNotNone(response.result.data.category)
        self.assertIsNotNone(response.result.data.verdict)
        self.assertIsNotNone(response.result.data.score)

    def test_url_reputation_with_bad_auth_token(self):
        token = "noarealtoken"
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test")
        badintel_url = UrlIntel(token, config=config)

        with self.assertRaises(pe.UnauthorizedException):
            badintel_url.reputation(url="http://113.235.101.11:54384", provider="crowdstrike")


class TestUserIntel(unittest.TestCase):
    def setUp(self):
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test")
        self.intel_user = UserIntel(token, config=config, logger_name="pangea")
        logger_set_pangea_config(logger_name=self.intel_user.logger.name)

    def test_user_breached_phone(self):
        response = self.intel_user.user_breached(phone_number="8005550123", provider="spycloud", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.found_in_breach)
        self.assertGreater(response.result.data.breach_count, 0)

    def test_user_breached_phone_bulk(self):
        response = self.intel_user.user_breached_bulk(
            phone_numbers=["8005550123", "8005550124"], provider="spycloud", verbose=True, raw=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response.result.data), 2)

    def test_user_breached_email(self):
        response = self.intel_user.user_breached(email="test@example.com", provider="spycloud", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.found_in_breach)
        self.assertGreater(response.result.data.breach_count, 0)

    def test_user_breached_email_bulk(self):
        response = self.intel_user.user_breached_bulk(
            emails=["test@example.com", "noreply@example.com"], provider="spycloud", verbose=True, raw=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response.result.data), 2)

    def test_user_breached_username(self):
        response = self.intel_user.user_breached(username="shortpatrick", provider="spycloud", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.found_in_breach)
        self.assertGreater(response.result.data.breach_count, 0)

    def test_user_breached_username_bulk(self):
        response = self.intel_user.user_breached_bulk(
            usernames=["shortpatrick", "user1"], provider="spycloud", verbose=True, raw=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response.result.data), 2)

    def test_user_breached_ip(self):
        response = self.intel_user.user_breached(ip="192.168.140.37", provider="spycloud", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.found_in_breach)
        self.assertGreater(response.result.data.breach_count, 0)

    def test_user_breached_ip_bulk(self):
        response = self.intel_user.user_breached_bulk(
            ips=["192.168.140.37", "1.1.1.1"], provider="spycloud", verbose=True, raw=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response.result.data), 2)

    def test_user_breached_default_provider(self):
        response = self.intel_user.user_breached(phone_number="8005550123", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)

    def test_password_breached(self):
        response = self.intel_user.password_breached(
            hash_prefix="5baa6", hash_type=HashType.SHA256, provider="spycloud"
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.found_in_breach)
        self.assertGreater(response.result.data.breach_count, 0)

    def test_password_breached_bulk(self):
        response = self.intel_user.password_breached_bulk(
            hash_prefixes=["5baa6", "5baa7"], hash_type=HashType.SHA256, provider="spycloud"
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response.result.data), 2)

    def test_password_breached_default_provider(self):
        response = self.intel_user.password_breached(hash_prefix="5baa6", hash_type=HashType.SHA256)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.found_in_breach)
        self.assertGreater(response.result.data.breach_count, 0)

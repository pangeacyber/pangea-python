import time
import unittest
from io import BytesIO

import pangea.exceptions as pe
from pangea import PangeaConfig
from pangea.response import ResponseStatus
from pangea.services import DomainIntel, FileIntel, FileScan, IpIntel, UrlIntel, UserIntel
from pangea.services.intel import HashType
from pangea.tools import TestEnvironment, get_test_domain, get_test_token, logger_set_pangea_config

TEST_ENVIRONMENT = TestEnvironment.DEVELOP


class TestDomainIntel(unittest.TestCase):
    def setUp(self):
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test")
        self.intel_domain = DomainIntel(token, config=config, logger_name="pangea")
        logger_set_pangea_config(logger_name=self.intel_domain.logger.name)

    def test_domain_reputation(self):
        response = self.intel_domain.reputation(
            domain="737updatesboeing.com", provider="domaintools", verbose=True, raw=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.verdict, "malicious")

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
        self.assertEqual(response.result.data.city, "unna")
        self.assertEqual(response.result.data.postal_code, "59425")

    def test_ip_domain(self):
        response = self.intel_ip.get_domain(ip="24.235.114.61", provider="digitalelement", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.domain_found)
        self.assertEqual("rogers.com", response.result.data.domain)

    def test_ip_domain_default_provider(self):
        response = self.intel_ip.get_domain(ip="24.235.114.61", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.domain_found)
        self.assertEqual("rogers.com", response.result.data.domain)

    def test_ip_vpn(self):
        response = self.intel_ip.is_vpn(ip="2.56.189.74", provider="digitalelement", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.is_vpn)

    def test_ip_vpn_default_provider(self):
        response = self.intel_ip.is_vpn(ip="2.56.189.74", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.is_vpn)

    def test_ip_proxy(self):
        response = self.intel_ip.is_proxy(ip="34.201.32.172", provider="digitalelement", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.is_proxy)

    def test_ip_proxy_default_provider(self):
        response = self.intel_ip.is_proxy(ip="34.201.32.172", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.is_proxy)

    def test_ip_reputation(self):
        response = self.intel_ip.reputation(ip="93.231.182.110", provider="crowdstrike", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.verdict, "malicious")

    def test_ip_reputation_cymru(self):
        response = self.intel_ip.reputation(ip="93.231.182.110", provider="cymru", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)

    def test_ip_reputation_default_provider(self):
        response = self.intel_ip.reputation(ip="93.231.182.110", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)

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

    def test_url_reputation_default_provider(self):
        response = self.intel_url.reputation(url="http://113.235.101.11:54384", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)

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

    def test_user_breached_email(self):
        response = self.intel_user.user_breached(email="test@example.com", provider="spycloud", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.found_in_breach)
        self.assertGreater(response.result.data.breach_count, 0)

    def test_user_breached_username(self):
        response = self.intel_user.user_breached(username="shortpatrick", provider="spycloud", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.found_in_breach)
        self.assertGreater(response.result.data.breach_count, 0)

    def test_user_breached_ip(self):
        response = self.intel_user.user_breached(ip="192.168.140.37", provider="spycloud", verbose=True, raw=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.found_in_breach)
        self.assertGreater(response.result.data.breach_count, 0)

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

    def test_password_breached_default_provider(self):
        response = self.intel_user.password_breached(hash_prefix="5baa6", hash_type=HashType.SHA256)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(response.result.data.found_in_breach)
        self.assertGreater(response.result.data.breach_count, 0)


EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n"


def eicar():
    bio = BytesIO()
    bio.write(EICAR)
    bio.seek(0)
    return bio


class TestFileScan(unittest.TestCase):
    def setUp(self):
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test", poll_result_timeout=120)
        self.scan = FileScan(token, config=config)
        logger_set_pangea_config(logger_name=self.scan.logger.name)

    def test_scan_file(self):
        response = self.scan.file_scan(file=eicar(), verbose=True, provider="reversinglabs")
        self.assertEqual(response.status, "Success")
        self.assertEqual(response.result.data.verdict, "malicious")
        self.assertEqual(response.result.data.score, 100)

    def test_scan_filepath(self):
        response = self.scan.file_scan(file_path="README.md", verbose=True, provider="reversinglabs")
        self.assertEqual(response.status, "Success")

    def test_scan_file_async(self):
        with self.assertRaises(pe.AcceptedRequestException):
            response = self.scan.file_scan(file=eicar(), verbose=True, provider="reversinglabs", sync_call=False)

    def test_scan_file_poll_result(self):
        exception = None
        try:
            response = self.scan.file_scan(file=eicar(), verbose=True, provider="reversinglabs", sync_call=False)
            self.assertTrue(False)
        except pe.AcceptedRequestException as e:
            exception = e

        # wait some time to get result ready and poll it
        time.sleep(120)

        response = self.scan.poll_result(exception)
        self.assertEqual(response.status, "Success")
        self.assertEqual(response.result.data.verdict, "malicious")
        self.assertEqual(response.result.data.score, 100)

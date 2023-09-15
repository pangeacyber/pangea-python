import time
import unittest

import pangea.exceptions as pe
from pangea import PangeaConfig
from pangea.services import FileScan
from pangea.tools import TestEnvironment, get_test_domain, get_test_token, logger_set_pangea_config

TEST_ENVIRONMENT = TestEnvironment.LIVE
PDF_FILEPATH = "./tests/testdata/testfile.pdf"


def get_test_file():
    return open(PDF_FILEPATH, "rb")


class TestFileScan(unittest.TestCase):
    def setUp(self):
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test", poll_result_timeout=120)
        self.scan = FileScan(token, config=config)
        logger_set_pangea_config(logger_name=self.scan.logger.name)

    def test_scan_file_crowdstrike(self):
        try:
            with get_test_file() as f:
                response = self.scan.file_scan(file=f, verbose=True, provider="crowdstrike")
                self.assertEqual(response.status, "Success")
                self.assertEqual(response.result.data.verdict, "benign")
                self.assertEqual(response.result.data.score, 0)
        except pe.PangeaAPIException as e:
            print(e)
            print(type(e))
            self.assertTrue(False)

    def test_scan_filepath_crowdstrike(self):
        response = self.scan.file_scan(file_path=PDF_FILEPATH, verbose=True, provider="crowdstrike")
        self.assertEqual(response.status, "Success")

    def test_scan_file_async_crowdstrike(self):
        with self.assertRaises(pe.AcceptedRequestException):
            with get_test_file() as f:
                response = self.scan.file_scan(file=f, verbose=True, provider="crowdstrike", sync_call=False)

    def test_scan_file_poll_result_crowdstrike(self):
        exception = None
        try:
            with get_test_file() as f:
                response = self.scan.file_scan(file=f, verbose=True, provider="crowdstrike", sync_call=False)
                self.assertTrue(False)
        except pe.AcceptedRequestException as e:
            exception = e

        for _ in range(6):
            try:
                # wait some time to get result ready and poll it
                time.sleep(10)

                response = self.scan.poll_result(exception)
                self.assertEqual(response.status, "Success")
                self.assertEqual(response.result.data.verdict, "benign")
                self.assertEqual(response.result.data.score, 0)
            except pe.PangeaAPIException:
                pass

    def test_scan_file_reversinglabs(self):
        try:
            with get_test_file() as f:
                response = self.scan.file_scan(file=f, verbose=True, provider="reversinglabs")
                self.assertEqual(response.status, "Success")
                self.assertEqual(response.result.data.verdict, "benign")
                self.assertEqual(response.result.data.score, 0)
        except pe.PangeaAPIException as e:
            print(e)
            print(type(e))
            self.assertTrue(False)

    def test_scan_filepath_reversinglabs(self):
        response = self.scan.file_scan(file_path=PDF_FILEPATH, verbose=True, provider="reversinglabs")
        self.assertEqual(response.status, "Success")

    def test_scan_file_async_reversinglabs(self):
        with self.assertRaises(pe.AcceptedRequestException):
            with get_test_file() as f:
                response = self.scan.file_scan(file=f, verbose=True, provider="reversinglabs", sync_call=False)

    def test_scan_file_poll_result_reversinglabs(self):
        exception = None
        try:
            with get_test_file() as f:
                response = self.scan.file_scan(file=f, verbose=True, provider="reversinglabs", sync_call=False)
                self.assertTrue(False)
        except pe.AcceptedRequestException as e:
            exception = e

        for _ in range(6):
            try:
                # wait some time to get result ready and poll it
                time.sleep(10)

                response = self.scan.poll_result(exception)
                self.assertEqual(response.status, "Success")
                self.assertEqual(response.result.data.verdict, "benign")
                self.assertEqual(response.result.data.score, 0)
                break
            except pe.PangeaAPIException:
                pass

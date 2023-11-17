import logging
import time
import unittest
from http.client import HTTPConnection

import pangea.exceptions as pe
from pangea import PangeaConfig
from pangea.response import PangeaResponse, TransferMethod
from pangea.services import FileScan
from pangea.services.file_scan import FileScanResult, FileUploader
from pangea.tools import TestEnvironment, get_test_domain, get_test_token, logger_set_pangea_config
from pangea.utils import get_file_upload_params

TEST_ENVIRONMENT = TestEnvironment.STAGING
PDF_FILEPATH = "./tests/testdata/testfile.pdf"


def get_test_file():
    return open(PDF_FILEPATH, "rb")


def debug_requests_on():
    """Switches on logging of the requests module."""
    HTTPConnection.debuglevel = 1

    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True


class TestFileScan(unittest.TestCase):
    def setUp(self):
        # debug_requests_on()
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test", poll_result_timeout=240)
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

    def test_scan_file_multipart(self):
        try:
            with get_test_file() as f:
                response = self.scan.file_scan(file=f, verbose=True, transfer_method=TransferMethod.MULTIPART)
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

        max_retry = 12
        for retry in range(max_retry):
            try:
                # wait some time to get result ready and poll it
                time.sleep(10)

                response = self.scan.poll_result(exception)
                self.assertEqual(response.status, "Success")
                self.assertEqual(response.result.data.verdict, "benign")
                self.assertEqual(response.result.data.score, 0)
                break
            except Exception:
                self.assertLess(retry, max_retry - 1)

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

        max_retry = 24
        for retry in range(max_retry):
            try:
                # wait some time to get result ready and poll it
                time.sleep(10)

                response = self.scan.poll_result(exception)
                self.assertEqual(response.status, "Success")
                self.assertEqual(response.result.data.verdict, "benign")
                self.assertEqual(response.result.data.score, 0)
                break
            except pe.PangeaAPIException:
                self.assertLess(retry, max_retry - 1)

    def test_split_upload_file_direct(self):
        with get_test_file() as f:
            params = get_file_upload_params(f)
            response = self.scan.get_upload_url(
                transfer_method=TransferMethod.DIRECT, params=params, verbose=True, provider="reversinglabs"
            )
            url = response.accepted_result.accepted_status.upload_url
            file_details = response.accepted_result.accepted_status.upload_details

            uploader = FileUploader()
            uploader.upload_file(url=url, file=f, transfer_method=TransferMethod.DIRECT, file_details=file_details)

        max_retry = 24
        for retry in range(max_retry):
            try:
                # wait some time to get result ready and poll it
                time.sleep(10)

                response: PangeaResponse[FileScanResult] = self.scan.poll_result(response=response)
                self.assertEqual(response.status, "Success")
                self.assertEqual(response.result.data.verdict, "benign")
                self.assertEqual(response.result.data.score, 0)
                break
            except pe.PangeaAPIException:
                self.assertLess(retry, max_retry - 1)

    def test_split_upload_file_post(self):
        with get_test_file() as f:
            params = get_file_upload_params(f)
            response = self.scan.get_upload_url(
                transfer_method=TransferMethod.POST_URL, params=params, verbose=True, provider="reversinglabs"
            )
            url = response.accepted_result.accepted_status.upload_url
            file_details = response.accepted_result.accepted_status.upload_details

            uploader = FileUploader()
            uploader.upload_file(url=url, file=f, transfer_method=TransferMethod.POST_URL, file_details=file_details)

        max_retry = 24
        for retry in range(max_retry):
            try:
                # wait some time to get result ready and poll it
                time.sleep(10)

                response: PangeaResponse[FileScanResult] = self.scan.poll_result(response=response)
                self.assertEqual(response.status, "Success")
                self.assertEqual(response.result.data.verdict, "benign")
                self.assertEqual(response.result.data.score, 0)
                break
            except pe.PangeaAPIException:
                self.assertLess(retry, max_retry - 1)

    def test_split_upload_file_put(self):
        with get_test_file() as f:
            response = self.scan.get_upload_url(
                transfer_method=TransferMethod.PUT_URL, verbose=True, provider="reversinglabs"
            )
            url = response.accepted_result.accepted_status.upload_url

            uploader = FileUploader()
            uploader.upload_file(url=url, file=f, transfer_method=TransferMethod.PUT_URL)

        max_retry = 24
        for retry in range(max_retry):
            try:

                # wait some time to get result ready and poll it
                time.sleep(10)

                response: PangeaResponse[FileScanResult] = self.scan.poll_result(response=response)
                self.assertEqual(response.status, "Success")
                self.assertEqual(response.result.data.verdict, "benign")
                self.assertEqual(response.result.data.score, 0)
                break
            except pe.PangeaAPIException:
                self.assertLess(retry, max_retry - 1)

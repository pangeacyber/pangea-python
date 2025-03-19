import time
import unittest
from asyncio import sleep
from contextlib import suppress

import pangea.exceptions as pe
from pangea import PangeaConfig
from pangea.asyncio.services import FileScanAsync
from pangea.asyncio.services.file_scan import FileUploaderAsync
from pangea.response import PangeaResponse, TransferMethod
from pangea.services.file_scan import FileScanResult
from pangea.tools import TestEnvironment, get_test_token, get_test_url_template, logger_set_pangea_config
from pangea.utils import get_file_upload_params
from tests.test_tools import load_test_environment

TEST_ENVIRONMENT = load_test_environment(FileScanAsync.service_name, TestEnvironment.LIVE)
PDF_FILEPATH = "./tests/testdata/testfile.pdf"


def get_test_file():
    return open(PDF_FILEPATH, "rb")


class TestFileScan(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        token = get_test_token(TEST_ENVIRONMENT)
        url_template = get_test_url_template(TEST_ENVIRONMENT)
        config = PangeaConfig(base_url_template=url_template, custom_user_agent="sdk-test", poll_result_timeout=240)
        self.scan = FileScanAsync(token, config=config)
        logger_set_pangea_config(logger_name=self.scan.logger.name)

    async def asyncTearDown(self):
        await self.scan.close()

    async def test_scan_file(self):
        try:
            with get_test_file() as f:
                response = await self.scan.file_scan(file=f, verbose=True, provider="crowdstrike")
                self.assertEqual(response.status, "Success")
                self.assertEqual(response.result.data.verdict, "benign")
                self.assertEqual(response.result.data.score, 0)
        except pe.PangeaAPIException as e:
            print(e)
            print(type(e))
            self.assertTrue(False)

    async def test_scan_file_multipart(self):
        try:
            with get_test_file() as f:
                response = await self.scan.file_scan(file=f, verbose=True, transfer_method=TransferMethod.MULTIPART)
                self.assertEqual(response.status, "Success")
                self.assertEqual(response.result.data.verdict, "benign")
                self.assertEqual(response.result.data.score, 0)
        except pe.PangeaAPIException as e:
            print(e)
            print(type(e))
            self.assertTrue(False)

    async def test_scan_filepath(self):
        response = await self.scan.file_scan(file_path=PDF_FILEPATH, verbose=True, provider="crowdstrike")
        self.assertEqual(response.status, "Success")

    async def test_scan_file_async(self):
        with self.assertRaises(pe.AcceptedRequestException):
            with get_test_file() as f:
                response = await self.scan.file_scan(file=f, verbose=True, provider="crowdstrike", sync_call=False)

    async def test_scan_file_poll_result(self):
        exception = None
        try:
            with get_test_file() as f:
                response = await self.scan.file_scan(file=f, verbose=True, provider="crowdstrike", sync_call=False)
                self.assertTrue(False)
        except pe.AcceptedRequestException as e:
            exception = e

        max_retry = 24
        for retry in range(max_retry):
            try:
                # wait some time to get result ready and poll it
                time.sleep(10)

                response = await self.scan.poll_result(exception)
                self.assertEqual(response.status, "Success")
                self.assertEqual(response.result.data.verdict, "benign")
                self.assertEqual(response.result.data.score, 0)
                break
            except pe.PangeaAPIException:
                self.assertLess(retry, max_retry - 1)

    async def test_split_upload_file_post(self):
        with get_test_file() as f:
            params = get_file_upload_params(f)
            response = await self.scan.request_upload_url(
                transfer_method=TransferMethod.POST_URL, params=params, verbose=True, provider="reversinglabs"
            )
            url = response.accepted_result.post_url
            file_details = response.accepted_result.post_form_data

            uploader = FileUploaderAsync()
            await uploader.upload_file(
                url=url, file=f, transfer_method=TransferMethod.POST_URL, file_details=file_details
            )
            await uploader.close()

        max_retry = 24
        for _ in range(max_retry):
            # wait some time to get result ready and poll it
            await sleep(10)

            with suppress(pe.AcceptedRequestException):
                response: PangeaResponse[FileScanResult] = await self.scan.poll_result(response=response)
                self.assertEqual(response.status, "Success")
                self.assertEqual(response.result.data.verdict, "benign")
                self.assertEqual(response.result.data.score, 0)
                break

    async def test_split_upload_file_put(self):
        with get_test_file() as f:
            response = await self.scan.request_upload_url(
                transfer_method=TransferMethod.PUT_URL, verbose=True, provider="reversinglabs"
            )
            url = response.accepted_result.put_url

            uploader = FileUploaderAsync()
            await uploader.upload_file(url=url, file=f, transfer_method=TransferMethod.PUT_URL)
            await uploader.close()

        max_retry = 24
        for _ in range(max_retry):
            # wait some time to get result ready and poll it
            await sleep(10)

            with suppress(pe.AcceptedRequestException):
                response: PangeaResponse[FileScanResult] = await self.scan.poll_result(response=response)
                self.assertEqual(response.status, "Success")
                self.assertEqual(response.result.data.verdict, "benign")
                self.assertEqual(response.result.data.score, 0)
                break

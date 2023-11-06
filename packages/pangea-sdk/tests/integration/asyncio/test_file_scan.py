import time
import unittest

import pangea.exceptions as pe
from pangea import PangeaConfig
from pangea.asyncio.services import FileScanAsync
from pangea.tools import TestEnvironment, get_test_domain, get_test_token, logger_set_pangea_config

TEST_ENVIRONMENT = TestEnvironment.LIVE
PDF_FILEPATH = "./tests/testdata/testfile.pdf"


def get_test_file():
    return open(PDF_FILEPATH, "rb")


class TestFileScan(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test", poll_result_timeout=240)
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

import logging
import time
import unittest
from http.client import HTTPConnection

import pangea.exceptions as pe
from pangea import PangeaConfig
from pangea.asyncio import FileUploaderAsync
from pangea.asyncio.services import SanitizeAsync
from pangea.response import PangeaResponse, TransferMethod
from pangea.services.sanitize import SanitizeContent, SanitizeFile, SanitizeResult, SanitizeShareOutput
from pangea.tools import TestEnvironment, get_test_domain, get_test_token, logger_set_pangea_config
from pangea.utils import get_file_upload_params
from tests.test_tools import load_test_environment

TEST_ENVIRONMENT = load_test_environment(SanitizeAsync.service_name, TestEnvironment.LIVE)
PDF_FILEPATH = "./tests/testdata/ds11.pdf"


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


class TestSanitize(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # debug_requests_on()
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test", poll_result_timeout=240)
        self.client = SanitizeAsync(token, config=config)
        logger_set_pangea_config(logger_name=self.client.logger.name)

    async def asyncTearDown(self):
        await self.client.close()

    async def test_sanitize_and_share(self):
        try:
            file_scan = SanitizeFile(scan_provider="crowdstrike", cdr_provider="apryse")
            content = SanitizeContent(
                url_intel=True,
                url_intel_provider="crowdstrike",
                domain_intel=True,
                domain_intel_provider="crowdstrike",
                defang=True,
                defang_threshold=20,
                remove_interactive=True,
                remove_attachments=True,
                redact=True,
            )
            share_output = SanitizeShareOutput(enabled=True, output_folder="sdk_test/sanitize/")
            with get_test_file() as f:
                response = await self.client.sanitize(
                    file=f,
                    transfer_method=TransferMethod.POST_URL,
                    file_scan=file_scan,
                    content=content,
                    share_output=share_output,
                    uploaded_file_name="uploaded_file",
                )
                self.assertEqual(response.status, "Success")
                self.assertIsNone(response.result.dest_url)
                self.assertIsNotNone(response.result.dest_share_id)
                self.assertGreater(response.result.data.redact.redaction_count, 0)
                self.assertNotEqual(response.result.data.redact.summary_counts, {})
                self.assertGreater(response.result.data.defang.external_urls_count, 0)
                self.assertGreater(response.result.data.defang.external_domains_count, 0)
                self.assertEqual(response.result.data.defang.defanged_count, 0)
                self.assertIsNotNone(response.result.data.defang.domain_intel_summary)
                self.assertEqual(response.result.data.cdr.file_attachments_removed, 0)
                self.assertEqual(response.result.data.cdr.interactive_contents_removed, 0)
                self.assertFalse(response.result.data.malicious_file)

        except pe.PangeaAPIException as e:
            print(e)
            print(type(e))
            self.assertTrue(False)

    async def test_sanitize_no_share(self):
        try:
            file_scan = SanitizeFile(scan_provider="crowdstrike", cdr_provider="apryse")
            content = SanitizeContent(
                url_intel=True,
                url_intel_provider="crowdstrike",
                domain_intel=True,
                domain_intel_provider="crowdstrike",
                defang=True,
                defang_threshold=20,
                remove_interactive=True,
                remove_attachments=True,
                redact=True,
            )
            share_output = SanitizeShareOutput(enabled=False)
            with get_test_file() as f:
                response = await self.client.sanitize(
                    file=f,
                    transfer_method=TransferMethod.POST_URL,
                    file_scan=file_scan,
                    content=content,
                    share_output=share_output,
                    uploaded_file_name="uploaded_file",
                )
                self.assertEqual(response.status, "Success")
                self.assertIsNotNone(response.result.dest_url)
                self.assertIsNone(response.result.dest_share_id)
                self.assertGreater(response.result.data.redact.redaction_count, 0)
                self.assertNotEqual(response.result.data.redact.summary_counts, {})
                self.assertGreater(response.result.data.defang.external_urls_count, 0)
                self.assertGreater(response.result.data.defang.external_domains_count, 0)
                self.assertEqual(response.result.data.defang.defanged_count, 0)
                self.assertIsNotNone(response.result.data.defang.domain_intel_summary)
                self.assertEqual(response.result.data.cdr.file_attachments_removed, 0)
                self.assertEqual(response.result.data.cdr.interactive_contents_removed, 0)
                self.assertFalse(response.result.data.malicious_file)

            attached_file = await self.client.download_file(response.result.dest_url)
            attached_file.save("./")

        except pe.PangeaAPIException as e:
            print(e)
            print(type(e))
            self.assertTrue(False)

    async def test_sanitize_all_defaults(self):
        try:
            with get_test_file() as f:
                response = await self.client.sanitize(
                    file=f,
                    transfer_method=TransferMethod.POST_URL,
                    uploaded_file_name="uploaded_file",
                )
                self.assertEqual(response.status, "Success")
                self.assertIsNotNone(response.result.dest_url)
                self.assertIsNone(response.result.dest_share_id)
                self.assertIsNone(response.result.data.redact)
                self.assertIsNotNone(response.result.data.defang)
                self.assertEqual(response.result.data.cdr.file_attachments_removed, 0)
                self.assertEqual(response.result.data.cdr.interactive_contents_removed, 0)
                self.assertFalse(response.result.data.malicious_file)
        except pe.PangeaAPIException as e:
            print(e)
            print(type(e))
            self.assertTrue(False)

    async def test_sanitize_multipart_upload(self):
        try:
            file_scan = SanitizeFile(scan_provider="crowdstrike", cdr_provider="apryse")
            content = SanitizeContent(
                url_intel=True,
                url_intel_provider="crowdstrike",
                domain_intel=True,
                domain_intel_provider="crowdstrike",
                defang=True,
                defang_threshold=20,
                remove_interactive=True,
                remove_attachments=True,
                redact=True,
            )
            share_output = SanitizeShareOutput(enabled=True, output_folder="sdk_test/sanitize/")
            with get_test_file() as f:
                response = await self.client.sanitize(
                    file=f,
                    transfer_method=TransferMethod.MULTIPART,
                    file_scan=file_scan,
                    content=content,
                    share_output=share_output,
                    uploaded_file_name="uploaded_file",
                )
                self.assertEqual(response.status, "Success")
                self.assertIsNone(response.result.dest_url)
                self.assertIsNotNone(response.result.dest_share_id)
                self.assertGreater(response.result.data.redact.redaction_count, 0)
                self.assertNotEqual(response.result.data.redact.summary_counts, {})
                self.assertGreater(response.result.data.defang.external_urls_count, 0)
                self.assertGreater(response.result.data.defang.external_domains_count, 0)
                self.assertEqual(response.result.data.defang.defanged_count, 0)
                self.assertIsNotNone(response.result.data.defang.domain_intel_summary)
                self.assertEqual(response.result.data.cdr.file_attachments_removed, 0)
                self.assertEqual(response.result.data.cdr.interactive_contents_removed, 0)
                self.assertFalse(response.result.data.malicious_file)

        except pe.PangeaAPIException as e:
            print(e)
            print(type(e))
            self.assertTrue(False)

    async def test_sanitize_async(self):
        with self.assertRaises(pe.AcceptedRequestException):
            with get_test_file() as f:
                response = await self.client.sanitize(
                    file=f, transfer_method=TransferMethod.POST_URL, uploaded_file_name="uploaded_file", sync_call=False
                )

    async def test_sanitize_filepath(self):
        try:
            file_scan = SanitizeFile(scan_provider="crowdstrike", cdr_provider="apryse")
            content = SanitizeContent(
                url_intel=True,
                url_intel_provider="crowdstrike",
                domain_intel=True,
                domain_intel_provider="crowdstrike",
                defang=True,
                defang_threshold=20,
                remove_interactive=True,
                remove_attachments=True,
                redact=True,
            )
            share_output = SanitizeShareOutput(enabled=True, output_folder="sdk_test/sanitize/")
            response = await self.client.sanitize(
                file_path=PDF_FILEPATH,
                transfer_method=TransferMethod.MULTIPART,
                file_scan=file_scan,
                content=content,
                share_output=share_output,
                uploaded_file_name="uploaded_file",
            )
            self.assertEqual(response.status, "Success")
            self.assertIsNone(response.result.dest_url)
            self.assertIsNotNone(response.result.dest_share_id)
            self.assertIsNotNone(response.result.data.redact)
            self.assertGreater(response.result.data.redact.redaction_count, 0)
            self.assertNotEqual(response.result.data.redact.summary_counts, {})
            self.assertIsNotNone(response.result.data.defang)
            self.assertGreater(response.result.data.defang.external_urls_count, 0)
            self.assertGreater(response.result.data.defang.external_domains_count, 0)
            self.assertEqual(response.result.data.defang.defanged_count, 0)
            self.assertIsNotNone(response.result.data.defang.domain_intel_summary)
            self.assertEqual(response.result.data.cdr.file_attachments_removed, 0)
            self.assertEqual(response.result.data.cdr.interactive_contents_removed, 0)
            self.assertFalse(response.result.data.malicious_file)
        except pe.PangeaAPIException as e:
            print(e)
            print(type(e))
            self.assertTrue(False)

    async def test_sanitize_poll_result(self):
        exception = None
        try:
            with get_test_file() as f:
                response = await self.client.sanitize(
                    file=f,
                    transfer_method=TransferMethod.MULTIPART,
                    uploaded_file_name="uploaded_file",
                    sync_call=False,
                )
                self.assertTrue(False)
        except pe.AcceptedRequestException as e:
            exception = e

        max_retry = 12
        for retry in range(max_retry):
            try:
                # wait some time to get result ready and poll it
                time.sleep(10)

                response: PangeaResponse[SanitizeResult] = await self.client.poll_result(exception)
                self.assertEqual(response.status, "Success")
                self.assertIsNotNone(response.result.dest_url)
                self.assertIsNone(response.result.dest_share_id)
                self.assertIsNone(response.result.data.redact)
                self.assertIsNotNone(response.result.data.defang)
                self.assertEqual(response.result.data.cdr.file_attachments_removed, 0)
                self.assertEqual(response.result.data.cdr.interactive_contents_removed, 0)
                self.assertFalse(response.result.data.malicious_file)
                break
            except pe.AcceptedRequestException:
                self.assertLess(retry, max_retry - 1)

    async def test_split_upload_file_post(self):
        file_scan = SanitizeFile(scan_provider="crowdstrike", cdr_provider="apryse")
        content = SanitizeContent(
            url_intel=True,
            url_intel_provider="crowdstrike",
            domain_intel=True,
            domain_intel_provider="crowdstrike",
            defang=True,
            defang_threshold=20,
            remove_interactive=True,
            remove_attachments=True,
            redact=True,
        )
        share_output = SanitizeShareOutput(enabled=False)
        with get_test_file() as f:
            params = get_file_upload_params(f)
            response = await self.client.request_upload_url(
                transfer_method=TransferMethod.POST_URL,
                file_scan=file_scan,
                content=content,
                share_output=share_output,
                params=params,
                uploaded_file_name="uploaded_file",
            )
            url = response.accepted_result.post_url
            file_details = response.accepted_result.post_form_data

            uploader = FileUploaderAsync()
            await uploader.upload_file(
                url=url, file=f, transfer_method=TransferMethod.POST_URL, file_details=file_details
            )
            await uploader.close()

        max_retry = 12
        for retry in range(max_retry):
            try:
                # wait some time to get result ready and poll it
                time.sleep(10)

                response: PangeaResponse[SanitizeResult] = await self.client.poll_result(response=response)
                self.assertEqual(response.status, "Success")
                self.assertIsNotNone(response.result.dest_url)
                self.assertIsNone(response.result.dest_share_id)
                self.assertIsNotNone(response.result.data.redact)
                self.assertGreater(response.result.data.redact.redaction_count, 0)
                self.assertNotEqual(response.result.data.redact.summary_counts, {})
                self.assertIsNotNone(response.result.data.defang)
                self.assertGreater(response.result.data.defang.external_urls_count, 0)
                self.assertGreater(response.result.data.defang.external_domains_count, 0)
                self.assertEqual(response.result.data.defang.defanged_count, 0)
                self.assertIsNotNone(response.result.data.defang.domain_intel_summary)
                self.assertEqual(response.result.data.cdr.file_attachments_removed, 0)
                self.assertEqual(response.result.data.cdr.file_attachments_removed, 0)
                self.assertEqual(response.result.data.cdr.interactive_contents_removed, 0)
                self.assertFalse(response.result.data.malicious_file)
                break
            except pe.AcceptedRequestException:
                self.assertLess(retry, max_retry - 1)

    async def test_split_upload_file_put(self):
        file_scan = SanitizeFile(scan_provider="crowdstrike", cdr_provider="apryse")
        content = SanitizeContent(
            url_intel=True,
            url_intel_provider="crowdstrike",
            domain_intel=True,
            domain_intel_provider="crowdstrike",
            defang=True,
            defang_threshold=20,
            remove_interactive=True,
            remove_attachments=True,
            redact=True,
        )
        share_output = SanitizeShareOutput(enabled=False)
        with get_test_file() as f:
            response = await self.client.request_upload_url(
                transfer_method=TransferMethod.PUT_URL,
                file_scan=file_scan,
                content=content,
                share_output=share_output,
                uploaded_file_name="uploaded_file",
            )
            url = response.accepted_result.put_url

            uploader = FileUploaderAsync()
            await uploader.upload_file(url=url, file=f, transfer_method=TransferMethod.PUT_URL)
            await uploader.close()

        max_retry = 12
        for retry in range(max_retry):
            try:
                # wait some time to get result ready and poll it
                time.sleep(10)

                response: PangeaResponse[SanitizeResult] = await self.client.poll_result(response=response)
                self.assertEqual(response.status, "Success")
                self.assertIsNotNone(response.result.dest_url)
                self.assertIsNone(response.result.dest_share_id)
                self.assertIsNotNone(response.result.data.redact)
                self.assertGreater(response.result.data.redact.redaction_count, 0)
                self.assertNotEqual(response.result.data.redact.summary_counts, {})
                self.assertIsNotNone(response.result.data.defang)
                self.assertGreater(response.result.data.defang.external_urls_count, 0)
                self.assertGreater(response.result.data.defang.external_domains_count, 0)
                self.assertEqual(response.result.data.defang.defanged_count, 0)
                self.assertIsNotNone(response.result.data.defang.domain_intel_summary)
                self.assertEqual(response.result.data.cdr.file_attachments_removed, 0)
                self.assertEqual(response.result.data.cdr.interactive_contents_removed, 0)
                self.assertFalse(response.result.data.malicious_file)
                break
            except pe.AcceptedRequestException:
                self.assertLess(retry, max_retry - 1)

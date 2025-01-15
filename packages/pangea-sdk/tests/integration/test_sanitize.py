from __future__ import annotations

import logging
import time
import unittest
from contextlib import suppress
from http.client import HTTPConnection
from io import BufferedReader
from pathlib import Path

import pangea.exceptions as pe
from pangea import FileUploader, PangeaConfig
from pangea.response import PangeaResponse, TransferMethod
from pangea.services import Sanitize
from pangea.services.sanitize import SanitizeContent, SanitizeFile, SanitizeResult, SanitizeShareOutput
from pangea.tools import TestEnvironment, get_custom_schema_test_token, get_test_domain, logger_set_pangea_config
from pangea.utils import get_file_upload_params
from tests.test_tools import load_test_environment

TEST_ENVIRONMENT = load_test_environment(Sanitize.service_name, TestEnvironment.LIVE)
PDF_FILEPATH = Path("./tests/testdata/test-sanitize.txt")


def get_test_file() -> BufferedReader:
    return PDF_FILEPATH.open("rb")


def debug_requests_on() -> None:
    """Switches on logging of the requests module."""
    HTTPConnection.debuglevel = 1

    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True


class TestSanitize(unittest.TestCase):
    log = logging.getLogger(__name__)

    def setUp(self) -> None:
        # debug_requests_on()

        # The Sanitize config in the regular org was obsoleted by a breaking
        # change, so the custom schema org is used instead.
        token = get_custom_schema_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test", poll_result_timeout=240)
        self.client = Sanitize(token, config=config)
        logger_set_pangea_config(logger_name=self.client.logger.name)

    def test_sanitize_and_share(self) -> None:
        with suppress(pe.AcceptedRequestException):
            file_scan = SanitizeFile(scan_provider="crowdstrike")
            content = SanitizeContent(
                url_intel=True,
                url_intel_provider="crowdstrike",
                domain_intel=True,
                domain_intel_provider="crowdstrike",
                defang=True,
                defang_threshold=20,
                redact=True,
            )
            share_output = SanitizeShareOutput(enabled=True, output_folder="sdk_test/sanitize/")
            with get_test_file() as f:
                response = self.client.sanitize(
                    file=f,
                    transfer_method=TransferMethod.POST_URL,
                    file_scan=file_scan,
                    content=content,
                    share_output=share_output,
                    uploaded_file_name="uploaded_file",
                )
                self.assertEqual(response.status, "Success")
                assert response.result
                self.assertIsNone(response.result.dest_url)
                self.assertIsNotNone(response.result.dest_share_id)
                assert response.result.data.redact
                self.assertGreater(response.result.data.redact.redaction_count, 0)
                self.assertNotEqual(response.result.data.redact.summary_counts, {})
                assert response.result.data.defang
                assert response.result.data.defang.external_urls_count
                self.assertGreater(response.result.data.defang.external_urls_count, 0)
                assert response.result.data.defang.external_domains_count
                self.assertGreater(response.result.data.defang.external_domains_count, 0)
                assert response.result.data.defang.defanged_count is not None
                self.assertEqual(response.result.data.defang.defanged_count, 0)
                self.assertIsNotNone(response.result.data.defang.domain_intel_summary)
                self.assertFalse(response.result.data.malicious_file)

    def test_sanitize_no_share(self) -> None:
        with suppress(pe.AcceptedRequestException):
            file_scan = SanitizeFile(scan_provider="crowdstrike")
            content = SanitizeContent(
                url_intel=True,
                url_intel_provider="crowdstrike",
                domain_intel=True,
                domain_intel_provider="crowdstrike",
                defang=True,
                defang_threshold=20,
                redact=True,
            )
            share_output = SanitizeShareOutput(enabled=False)
            with get_test_file() as f:
                response = self.client.sanitize(
                    file=f,
                    transfer_method=TransferMethod.POST_URL,
                    file_scan=file_scan,
                    content=content,
                    share_output=share_output,
                    uploaded_file_name="uploaded_file",
                )
                self.assertEqual(response.status, "Success")
                assert response.result
                assert response.result.dest_url
                self.assertIsNone(response.result.dest_share_id)
                assert response.result.data.redact
                self.assertGreater(response.result.data.redact.redaction_count, 0)
                self.assertNotEqual(response.result.data.redact.summary_counts, {})
                assert response.result.data.defang
                assert response.result.data.defang.external_urls_count
                self.assertGreater(response.result.data.defang.external_urls_count, 0)
                assert response.result.data.defang.external_domains_count
                self.assertGreater(response.result.data.defang.external_domains_count, 0)
                self.assertEqual(response.result.data.defang.defanged_count, 0)
                self.assertIsNotNone(response.result.data.defang.domain_intel_summary)
                self.assertFalse(response.result.data.malicious_file)

            attached_file = self.client.download_file(response.result.dest_url)
            attached_file.save("./")

    def test_sanitize_all_defaults(self) -> None:
        with suppress(pe.AcceptedRequestException), get_test_file() as f:
            response = self.client.sanitize(
                file=f,
                transfer_method=TransferMethod.POST_URL,
                uploaded_file_name="uploaded_file",
            )
            self.assertEqual(response.status, "Success")
            assert response.result
            self.assertIsNotNone(response.result.dest_url)
            self.assertIsNone(response.result.dest_share_id)
            self.assertIsNone(response.result.data.redact)
            self.assertIsNotNone(response.result.data.defang)
            self.assertFalse(response.result.data.malicious_file)

    def test_sanitize_multipart_upload(self) -> None:
        with suppress(pe.AcceptedRequestException):
            file_scan = SanitizeFile(scan_provider="crowdstrike")
            content = SanitizeContent(
                url_intel=True,
                url_intel_provider="crowdstrike",
                domain_intel=True,
                domain_intel_provider="crowdstrike",
                defang=True,
                defang_threshold=20,
                redact=True,
            )
            share_output = SanitizeShareOutput(enabled=True, output_folder="sdk_test/sanitize/")
            with get_test_file() as f:
                response = self.client.sanitize(
                    file=f,
                    transfer_method=TransferMethod.MULTIPART,
                    file_scan=file_scan,
                    content=content,
                    share_output=share_output,
                    uploaded_file_name="uploaded_file",
                )
                self.assertEqual(response.status, "Success")
                assert response.result
                self.assertIsNone(response.result.dest_url)
                self.assertIsNotNone(response.result.dest_share_id)
                assert response.result.data.redact
                self.assertGreater(response.result.data.redact.redaction_count, 0)
                self.assertNotEqual(response.result.data.redact.summary_counts, {})
                assert response.result.data.defang
                assert response.result.data.defang.external_urls_count
                self.assertGreater(response.result.data.defang.external_urls_count, 0)
                assert response.result.data.defang.external_domains_count
                self.assertGreater(response.result.data.defang.external_domains_count, 0)
                self.assertEqual(response.result.data.defang.defanged_count, 0)
                self.assertIsNotNone(response.result.data.defang.domain_intel_summary)
                self.assertFalse(response.result.data.malicious_file)

    def test_sanitize_async(self) -> None:
        with self.assertRaises(pe.AcceptedRequestException), get_test_file() as f:
            self.client.sanitize(
                file=f, transfer_method=TransferMethod.POST_URL, uploaded_file_name="uploaded_file", sync_call=False
            )

    def test_sanitize_filepath(self) -> None:
        with suppress(pe.AcceptedRequestException):
            file_scan = SanitizeFile(scan_provider="crowdstrike")
            content = SanitizeContent(
                url_intel=True,
                url_intel_provider="crowdstrike",
                domain_intel=True,
                domain_intel_provider="crowdstrike",
                defang=True,
                defang_threshold=20,
                redact=True,
            )
            share_output = SanitizeShareOutput(enabled=True, output_folder="sdk_test/sanitize/")
            response = self.client.sanitize(
                file_path=str(PDF_FILEPATH),
                transfer_method=TransferMethod.MULTIPART,
                file_scan=file_scan,
                content=content,
                share_output=share_output,
                uploaded_file_name="uploaded_file",
            )
            self.assertEqual(response.status, "Success")
            assert response.result
            self.assertIsNone(response.result.dest_url)
            self.assertIsNotNone(response.result.dest_share_id)
            assert response.result.data.redact
            self.assertGreater(response.result.data.redact.redaction_count, 0)
            self.assertNotEqual(response.result.data.redact.summary_counts, {})
            assert response.result.data.defang
            assert response.result.data.defang.external_urls_count
            self.assertGreater(response.result.data.defang.external_urls_count, 0)
            assert response.result.data.defang.external_domains_count
            self.assertGreater(response.result.data.defang.external_domains_count, 0)
            self.assertEqual(response.result.data.defang.defanged_count, 0)
            self.assertIsNotNone(response.result.data.defang.domain_intel_summary)
            self.assertFalse(response.result.data.malicious_file)

    def test_sanitize_poll_result(self) -> None:
        exception = None
        try:
            with get_test_file() as f:
                response = self.client.sanitize(
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

                response: PangeaResponse[SanitizeResult] = self.client.poll_result(exception)  # type: ignore[no-redef]
                self.assertEqual(response.status, "Success")
                assert response.result
                self.assertIsNotNone(response.result.dest_url)
                self.assertIsNone(response.result.dest_share_id)
                self.assertIsNone(response.result.data.redact)
                self.assertIsNotNone(response.result.data.defang)
                self.assertFalse(response.result.data.malicious_file)
                break
            except pe.AcceptedRequestException:
                self.assertLess(retry, max_retry - 1)

    def test_split_upload_file_post(self) -> None:
        file_scan = SanitizeFile(scan_provider="crowdstrike")
        content = SanitizeContent(
            url_intel=True,
            url_intel_provider="crowdstrike",
            domain_intel=True,
            domain_intel_provider="crowdstrike",
            defang=True,
            defang_threshold=20,
            redact=True,
        )
        share_output = SanitizeShareOutput(enabled=False)
        with get_test_file() as f:
            params = get_file_upload_params(f)
            response = self.client.request_upload_url(
                transfer_method=TransferMethod.POST_URL,
                file_scan=file_scan,
                content=content,
                share_output=share_output,
                params=params,
                uploaded_file_name="uploaded_file",
            )
            assert response.accepted_result
            assert response.accepted_result.post_url
            url = response.accepted_result.post_url
            file_details = response.accepted_result.post_form_data

            uploader = FileUploader()
            uploader.upload_file(url=url, file=f, transfer_method=TransferMethod.POST_URL, file_details=file_details)

        max_retry = 12
        for retry in range(max_retry):
            try:
                # wait some time to get result ready and poll it
                time.sleep(10)

                response: PangeaResponse[SanitizeResult] = self.client.poll_result(response=response)  # type: ignore[no-redef]
                self.assertEqual(response.status, "Success")
                assert response.result
                self.assertIsNotNone(response.result.dest_url)
                self.assertIsNone(response.result.dest_share_id)
                assert response.result.data.redact
                self.assertGreater(response.result.data.redact.redaction_count, 0)
                self.assertNotEqual(response.result.data.redact.summary_counts, {})
                assert response.result.data.defang
                assert response.result.data.defang.external_urls_count
                self.assertGreater(response.result.data.defang.external_urls_count, 0)
                assert response.result.data.defang.external_domains_count
                self.assertGreater(response.result.data.defang.external_domains_count, 0)
                self.assertEqual(response.result.data.defang.defanged_count, 0)
                self.assertIsNotNone(response.result.data.defang.domain_intel_summary)
                self.assertFalse(response.result.data.malicious_file)
                break
            except pe.AcceptedRequestException:
                self.assertLess(retry, max_retry - 1)

    def test_split_upload_file_put(self) -> None:
        file_scan = SanitizeFile(scan_provider="crowdstrike")
        content = SanitizeContent(
            url_intel=True,
            url_intel_provider="crowdstrike",
            domain_intel=True,
            domain_intel_provider="crowdstrike",
            defang=True,
            defang_threshold=20,
            redact=True,
        )
        share_output = SanitizeShareOutput(enabled=False)
        with get_test_file() as f:
            response = self.client.request_upload_url(
                transfer_method=TransferMethod.PUT_URL,
                file_scan=file_scan,
                content=content,
                share_output=share_output,
                uploaded_file_name="uploaded_file",
            )
            assert response.accepted_result
            assert response.accepted_result.put_url
            url = response.accepted_result.put_url

            uploader = FileUploader()
            uploader.upload_file(url=url, file=f, transfer_method=TransferMethod.PUT_URL)

        for _ in range(12):
            try:
                # wait some time to get result ready and poll it
                time.sleep(10)

                response: PangeaResponse[SanitizeResult] = self.client.poll_result(response=response)  # type: ignore[no-redef]
                self.assertEqual(response.status, "Success")
                assert response.result
                self.assertIsNotNone(response.result.dest_url)
                self.assertIsNone(response.result.dest_share_id)
                assert response.result.data.redact
                self.assertGreater(response.result.data.redact.redaction_count, 0)
                self.assertNotEqual(response.result.data.redact.summary_counts, {})
                assert response.result.data.defang
                assert response.result.data.defang.external_urls_count
                self.assertGreater(response.result.data.defang.external_urls_count, 0)
                assert response.result.data.defang.external_domains_count
                self.assertGreater(response.result.data.defang.external_domains_count, 0)
                self.assertEqual(response.result.data.defang.defanged_count, 0)
                self.assertIsNotNone(response.result.data.defang.domain_intel_summary)
                self.assertFalse(response.result.data.malicious_file)
                return
            except pe.AcceptedRequestException:
                pass

        self.log.warning("The result of request '%s' took too long to be ready.", response.request_id)

from unittest import TestCase

from pangea.config import PangeaConfig
from pangea.response import TransferMethod
from pangea.services.file_scan import FileScan


class TestFileScan(TestCase):
    def test_required_inputs(self) -> None:
        client = FileScan("not a token", config=PangeaConfig(base_url_template="not a domain"))

        # Need to set one of `file_path`, `file`, or `source_url` arguments.
        with self.assertRaisesRegex(ValueError, "Need to set one of"):
            client.file_scan()

    def test_source_url_validation(self) -> None:
        client = FileScan("not a token", config=PangeaConfig(base_url_template="not a domain"))

        # `source_url` with a different transfer method.
        with self.assertRaisesRegex(ValueError, "`transfer_method` should be `TransferMethod.SOURCE_URL`"):
            client.file_scan(
                transfer_method=TransferMethod.POST_URL, source_url="https://pangea.cloud/docs/img/favicon.ico"
            )

        # Missing `source_url`.
        with self.assertRaisesRegex(ValueError, "`source_url` argument is required"):
            client.file_scan(transfer_method=TransferMethod.SOURCE_URL)

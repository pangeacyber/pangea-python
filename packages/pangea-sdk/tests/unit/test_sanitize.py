from unittest import TestCase

from pangea.config import PangeaConfig
from pangea.response import TransferMethod
from pangea.services.sanitize import Sanitize


class TestSanitize(TestCase):
    def test_required_inputs(self) -> None:
        client = Sanitize("not a token", config=PangeaConfig(base_url_template="not a domain"))

        # Need to set one of `file_path`, `file`, or `source_url` arguments.
        with self.assertRaisesRegex(ValueError, "Need to set one of"):
            client.sanitize()

    def test_source_url_validation(self) -> None:
        client = Sanitize("not a token", config=PangeaConfig(base_url_template="not a domain"))

        # `source_url` with a different transfer method.
        with self.assertRaisesRegex(ValueError, "`transfer_method` should be `TransferMethod.SOURCE_URL`"):
            client.sanitize(
                transfer_method=TransferMethod.POST_URL, source_url="https://pangea.cloud/docs/img/favicon.ico"
            )

        # Missing `source_url`.
        with self.assertRaisesRegex(ValueError, "`source_url` argument is required"):
            client.sanitize(transfer_method=TransferMethod.SOURCE_URL)

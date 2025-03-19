import unittest
from urllib.parse import urljoin

from pangea.config import PangeaConfig
from pangea.services.audit.audit import Audit

token = "faketoken"
url_template = "https://{SERVICE_NAME}.aws.us.pangea.cloud/"
path = "path"


class TestConfig(unittest.TestCase):
    def test_base_url_template(self) -> None:
        config = PangeaConfig(base_url_template=url_template)
        audit = Audit(token, config=config)
        url = audit.request._url(path)
        url_reference = url_template.replace("{SERVICE_NAME}", audit.service_name)
        url_reference = urljoin(url_reference, path)
        self.assertEqual(url_reference, url)

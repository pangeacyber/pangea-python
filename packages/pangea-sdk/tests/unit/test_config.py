import unittest

from pangea.config import PangeaConfig
from pangea.services.audit.audit import Audit

token = "faketoken"
domain = "domain.test"
path = "path"
subdomain = "audit."


class TestConfig(unittest.TestCase):
    def test_insecure_true_environment_local(self):
        config = PangeaConfig(domain=domain, insecure=True, environment="local")
        audit = Audit(token, config=config)
        url = audit.request._url(path)
        self.assertEqual(f"http://{domain}/{path}", url)

    def test_insecure_false_environment_local(self):
        config = PangeaConfig(domain=domain, insecure=False, environment="local")
        audit = Audit(token, config=config)
        url = audit.request._url(path)
        self.assertEqual(f"https://{domain}/{path}", url)

    def test_insecure_true_environment_production(self):
        config = PangeaConfig(domain=domain, insecure=True, environment="production")
        audit = Audit(token, config=config)
        url = audit.request._url(path)
        self.assertEqual(f"http://{subdomain}{domain}/{path}", url)

    def test_insecure_false_environment_production(self):
        config = PangeaConfig(domain=domain, insecure=False, environment="production")
        audit = Audit(token, config=config)
        url = audit.request._url(path)
        self.assertEqual(f"https://{subdomain}{domain}/{path}", url)

    def test_insecure_default_environment_default(self):
        config = PangeaConfig(domain=domain)
        audit = Audit(token, config=config)
        url = audit.request._url(path)
        self.assertEqual(f"https://{subdomain}{domain}/{path}", url)

    def test_url(self):
        url = "http://myurldomain.net"
        config = PangeaConfig(domain=url)
        audit = Audit(token, config=config)
        url = audit.request._url(path)
        self.assertEqual(f"{url}/{path}", url)

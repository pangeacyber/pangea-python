from __future__ import annotations

import unittest

from pangea.config import PangeaConfig
from pangea.services.audit.audit import Audit

token = "faketoken"
domain = "domain.test"
path = "path"
subdomain = "audit."


class TestConfig(unittest.TestCase):
    def test_base_url_template(self) -> None:
        config = PangeaConfig(base_url_template="https://example.org/{SERVICE_NAME}")
        audit = Audit(token, config=config)
        assert audit.request._url("api") == "https://example.org/audit/api"

        config = PangeaConfig(base_url_template="https://example.org")
        audit = Audit(token, config=config)
        assert audit.request._url("api") == "https://example.org/api"

    def test_domain(self) -> None:
        config = PangeaConfig(domain="example.org")
        audit = Audit(token, config=config)
        assert audit.request._url("api") == "https://audit.example.org/api"

    def test_template_and_domain(self) -> None:
        """Should prefer template over domain."""

        config = PangeaConfig(base_url_template="https://example.org/{SERVICE_NAME}", domain="example.net")
        audit = Audit(token, config=config)
        assert audit.request._url("api") == "https://example.org/audit/api"

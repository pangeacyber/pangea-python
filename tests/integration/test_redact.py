import os
import unittest

from pangea import PangeaConfig
from pangea.services import Redact


class TestRedact(unittest.TestCase):
    def setUp(self):
        token = os.getenv("PANGEA_TOKEN")
        config_id = os.getenv("REDACT_CONFIG_ID")
        config = PangeaConfig(base_domain="dev.pangea.cloud", config_id=config_id)
        self.redact = Redact(token, config=config)

    def test_redact(self):
        pass

    def test_redact_structured(self):
        pass

import os
import unittest

from pangea import PangeaConfig
from pangea.services import Embargo


class TestEmbargo(unittest.TestCase):
    def setUp(self):
        token = os.getenv("PANGEA_TOKEN")
        config_id = os.getenv("EMBARGO_CONFIG_ID")
        config = PangeaConfig(base_domain="dev.pangea.cloud", config_id=config_id)
        self.embargo = Embargo(token, config=config)

    def test_ip_check(self):
        pass

    def test_iso_check(self):
        pass

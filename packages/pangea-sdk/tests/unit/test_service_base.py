import unittest

from pangea.services.base import PangeaConfig, ServiceBase


class TestServiceBase(unittest.TestCase):
    def test_service_base(self):
        token = "token"
        base = ServiceBase(token, PangeaConfig("domain"))
        self.assertEqual(token, base.token)

        base.token = "newtoken"
        self.assertEqual("newtoken", base.token)

    def test_service_base_no_token(self):
        def no_token():
            base = ServiceBase(None, PangeaConfig("domain"))

        # This should fail because there is no signed configured
        self.assertRaises(Exception, no_token)

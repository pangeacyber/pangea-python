import unittest

from pangea.services.audit.util import b64decode, b64decode_ascii, b64encode, b64encode_ascii
from pangea.utils import str2str_b64


class TestAuditUtil(unittest.TestCase):
    def test_base64(self):
        msg = "message"
        msg_b64 = str2str_b64(msg)
        out = b64encode(b64decode(msg_b64))
        self.assertEqual(msg_b64, out)

    def test_base64_ascii(self):
        msg = "message"
        msg_b64 = str2str_b64(msg)
        out = b64encode_ascii(b64decode_ascii(msg_b64))
        self.assertEqual(msg_b64, out)

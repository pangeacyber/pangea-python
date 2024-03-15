import unittest

from google_crc32c import Checksum as CRC32C  # type: ignore[import-untyped]

from pangea.services.audit.util import b64decode, b64decode_ascii, b64encode, b64encode_ascii
from pangea.utils import default_encoder, get_prefix, hash_sha1, hash_sha256, str2str_b64


class TestUtils(unittest.TestCase):
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

    def test_default_encoder(self):
        self.assertEqual("test", default_encoder("test"))

    def test_hash_sha1(self):
        self.assertEqual("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", hash_sha1("test"))

    def test_hash_sha256(self):
        self.assertEqual("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", hash_sha256("test"))

    def test_hash_prefix(self):
        hash = "123456789"
        self.assertEqual("12345", get_prefix(hash))
        self.assertEqual("123", get_prefix(hash, 3))

    def test_crc32c(self):
        crc = CRC32C()
        crc.update("ABCDEF".encode("ascii"))
        self.assertEqual(crc.hexdigest().decode("utf-8"), "a4b7ce68")

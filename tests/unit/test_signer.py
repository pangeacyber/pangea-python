import unittest

import pangea.exceptions as pexc
from pangea.signing import Signer


class TestSigner(unittest.TestCase):
    def test_signer(self):
        signer = Signer("./tests/testdata/privkey")
        pubkey = signer.getPublicKeyBytes()
        signature = signer.signMessage("signthismessage")
        self.assertNotEqual(pubkey, {})
        self.assertEqual(
            signature, "yRqaZIAXEuhaCN6n7inzQVdn0Zdh947cDbF1sS+YPQGl6vyEGesBdkuDjbo1HlcHk11BgJYXu30ZfrNx/BY1Bg=="
        )

    def test_signer_no_file(self):
        with self.assertRaises(Exception):
            filename = "./not/a/file"
            signer = Signer(filename)
            pubkey = signer.getPublicKeyBytes()
            self.assertTrue(False)

    def test_signer_bad_format(self):
        with self.assertRaises(Exception):
            filename = "./tests/testdata/badformatprivkey"
            signer = Signer(filename)
            pubkey = signer.getPublicKeyBytes()
            self.assertTrue(False)

    def test_signer_no_ed25519(self):
        with self.assertRaises(Exception):
            filename = "./tests/testdata/noed25519privkey"
            signer = Signer(filename)
            pubkey = signer.getPublicKeyBytes()
            self.assertTrue(False)

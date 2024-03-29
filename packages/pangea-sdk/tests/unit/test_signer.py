import unittest

from pangea.services.audit.signing import Signer, Verifier


class TestSigner(unittest.TestCase):
    def test_signer(self):
        msg = "signthismessage"
        signer = Signer("./tests/testdata/privkey")
        pubkey = signer.get_public_key_PEM()
        pubkey_bytes = "MCowBQYDK2VwAyEAlvOyDMpK2DQ16NI8G41yINl01wMHzINBahtDPoh4+mE="
        signature_expected = "yRqaZIAXEuhaCN6n7inzQVdn0Zdh947cDbF1sS+YPQGl6vyEGesBdkuDjbo1HlcHk11BgJYXu30ZfrNx/BY1Bg=="
        signature = signer.sign(bytes(msg, "utf-8"))
        self.assertEqual(
            pubkey,
            "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAlvOyDMpK2DQ16NI8G41yINl01wMHzINBahtDPoh4+mE=\n-----END PUBLIC KEY-----\n",
        )
        self.assertEqual(signature, signature_expected)

        v = Verifier()
        verification = v.verify_signature(signature, bytes(msg, "utf8"), pubkey)
        self.assertTrue(verification)

        # Verify old format public key
        verification = v.verify_signature(signature, bytes(msg, "utf8"), pubkey_bytes)
        self.assertTrue(verification)

    def test_signer_no_file(self):
        with self.assertRaises(Exception):
            filename = "./not/a/file"
            signer = Signer(filename)
            pubkey = signer.get_public_key_PEM()

    def test_signer_bad_format(self):
        with self.assertRaises(Exception):
            filename = "./tests/testdata/badformatprivkey"
            signer = Signer(filename)
            pubkey = signer.get_public_key_PEM()

    def test_signer_no_ed25519(self):
        with self.assertRaises(Exception):
            filename = "./tests/testdata/noed25519privkey"
            signer = Signer(filename)
            pubkey = signer.get_public_key_PEM()

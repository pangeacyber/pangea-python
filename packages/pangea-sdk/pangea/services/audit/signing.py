# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from base64 import b64decode, b64encode
from typing import Dict, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from pangea.services.audit.util import b64decode_ascii, canonicalize_json


class Signer:
    def __init__(self, private_key_file: str) -> None:
        self._private_key = None
        self._private_key_filename = private_key_file

    # Returns the private key
    def _getPrivateKey(self) -> ed25519.Ed25519PrivateKey:
        if self._private_key is None:
            try:
                with open(self._private_key_filename, "rb") as file:
                    file_bytes = file.read()
            except FileNotFoundError:
                raise Exception(f"Error: Failed opening private key file {self._private_key_filename}")

            try:
                self._private_key = serialization.load_pem_private_key(file_bytes, None)
            except Exception:
                self._private_key = None
                raise Exception("Error: Failed loading private key.")

            if not isinstance(self._private_key, ed25519.Ed25519PrivateKey):
                self._private_key = None
                raise Exception("Private key is not using Ed25519 algorithm.")

        return self._private_key

    # Signs a message in bytes using Ed25519 algorithm
    def _signMessageBytes(self, message_bytes: bytes, private_key: ed25519.Ed25519PrivateKey) -> str:
        try:
            signature = private_key.sign(message_bytes)
            signature_b64 = b64encode(signature).decode("ascii")
        except Exception:
            return None

        return signature_b64

    # Signs a string message using Ed25519 algorithm
    def _signMessageStr(self, message: str, private_key: ed25519.Ed25519PrivateKey) -> str:
        message_bytes = bytes(message, "utf8")
        return self._signMessageBytes(message_bytes, private_key)

    # Signs a JSON message using Ed25519 algorithm
    def _signMessageJSON(self, messageJSON: dict, private_key: ed25519.Ed25519PrivateKey) -> str:
        message_bytes = canonicalize_json(messageJSON)
        return self._signMessageBytes(message_bytes, private_key)

    def signMessage(self, message: Union[str, Dict, bytes]) -> str:
        private_key = self._getPrivateKey()

        if isinstance(message, str):
            return self._signMessageStr(message, private_key)

        elif isinstance(message, dict):
            return self._signMessageJSON(message, private_key)

        elif isinstance(message, bytes):
            return self._signMessageBytes(message, private_key)
        else:
            raise Exception("Error: Not supported instance")

    def getPublicKeyBytes(self):
        return (
            self._getPrivateKey()
            .public_key()
            .public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        )


class Verifier:
    # verify message with signature and public key bytes
    def verifyMessage(self, signature_b64: str, message: Union[str, dict, bytes], public_key_b64: str = None) -> bool:
        public_key_bytes = b64decode_ascii(public_key_b64)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)

        if isinstance(message, str):
            return self._verifyMessageStr(signature_b64, message, public_key)
        elif isinstance(message, dict):
            return self._verifyMessageJSON(signature_b64, message, public_key)
        elif isinstance(message, bytes):
            return self._verifyMessageBytes(signature_b64, message, public_key)
        else:
            raise Exception("Error: Not supported instance")

    # Verify a message in bytes using Ed25519 algorithm
    def _verifyMessageBytes(
        self, signature_b64: str, message_bytes: bytes, public_key: ed25519.Ed25519PublicKey
    ) -> bool:
        try:
            signature = b64decode(signature_b64)
            public_key.verify(signature, message_bytes)
        except Exception:
            return False

        return True

    # Verify a string message using Ed25519 algorithm
    def _verifyMessageStr(self, signature_b64: str, message: str, public_key: ed25519.Ed25519PublicKey) -> bool:
        message_bytes = bytes(message, "utf8")
        return self._verifyMessageBytes(signature_b64, message_bytes, public_key)

    # Verify a JSON message using Ed25519 algorithm
    def _verifyMessageJSON(self, signature_b64: str, messageJSON: dict, public_key: ed25519.Ed25519PublicKey) -> bool:
        message_bytes = canonicalize_json(messageJSON)
        return self._verifyMessageBytes(signature_b64, message_bytes, public_key)

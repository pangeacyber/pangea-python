# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from abc import ABC, abstractmethod
from base64 import b64decode, b64encode
from typing import Dict, Optional, Union

from cryptography import exceptions
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pangea.exceptions import PangeaException
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

    def getPublicKeyBytes(self) -> bytes:
        return (
            self._getPrivateKey()
            .public_key()
            .public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        )

    def getPublicKeyPEM(self) -> str:
        return (
            self._getPrivateKey()
            .public_key()
            .public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode("utf-8")
        )


class AlgorithmVerifier(ABC):
    def __init__(self, public_key):
        self.public_key = public_key

    @abstractmethod
    def verify(self, message: bytes, signature: bytes) -> bool:
        pass


class ED25519Verifier(AlgorithmVerifier):
    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self.public_key.verify(signature, message)
            return True
        except exceptions.InvalidSignature:
            return False


verifiers = {
    ed25519.Ed25519PublicKey: ED25519Verifier,
}


class Verifier:
    # verify message with signature and public key bytes
    def verify_signature(
        self, signature_b64: str, message_bytes: bytes, public_key_input: str = None
    ) -> Optional[bool]:
        if self._is_pem_format(public_key_input):
            pubkey = self._decode_public_key(bytes(public_key_input, "utf-8"))
        else:
            # To make backward compatible with original public keys send encoded bytes in base64
            public_key_bytes = b64decode_ascii(public_key_input)
            pubkey = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)

        signature_bytes = b64decode(signature_b64)
        for cls, verifier in verifiers.items():
            if isinstance(pubkey, cls):
                return verifier(pubkey).verify(message_bytes, signature_bytes)
        else:
            raise PangeaException(f"Not supported public key type: {type(pubkey)}")

    def _decode_public_key(self, public_key: bytes):
        """Parse a public key in PEM or ssh format"""

        for func in (serialization.load_pem_public_key, serialization.load_ssh_public_key):
            try:
                return func(public_key)
            except exceptions.UnsupportedAlgorithm as e:
                raise e
            except ValueError:
                pass

        raise PangeaException("Unsupported key")

    def _is_pem_format(self, key: str) -> bool:
        return key.startswith("-----")

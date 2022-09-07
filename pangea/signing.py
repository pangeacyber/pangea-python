# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import os
import typing as t
from base64 import b64decode, b64encode

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .services.audit_util import canonicalize_json


class Signer:
    def __init__(self, private_key_file: str) -> None:
        self.__private_key = None
        self.__private_key_filename = private_key_file

    # Returns the private key
    def __getPrivateKey(self) -> ed25519.Ed25519PrivateKey:
        if self.__private_key is None:
            try:
                with open(self.__private_key_filename, "rb") as file:
                    file_bytes = file.read()
            except Exception:
                print(os.getcwdb())
                raise Exception(f"Error: Failed opening private key file {self.__private_key_filename}")

            try:
                self.__private_key = serialization.load_pem_private_key(file_bytes, None)
            except Exception:
                self.__private_key = None
                raise Exception("Error: Failed loading private key.")

            if not isinstance(self.__private_key, ed25519.Ed25519PrivateKey):
                self.__private_key = None
                raise Exception("Private key is not using Ed25519 algorithm.")

        return self.__private_key

    # Signs a message in bytes using Ed25519 algorithm
    def __signMessageBytes(self, message_bytes: bytes, private_key: ed25519.Ed25519PrivateKey):
        try:
            signature = private_key.sign(message_bytes)
            signature_b64 = b64encode(signature).decode("ascii")
        except Exception:
            return None

        return signature_b64

    # Signs a string message using Ed25519 algorithm
    def __signMessageStr(self, message: str, private_key: ed25519.Ed25519PrivateKey):
        message_bytes = bytes(message, "utf8")
        return self.__signMessageBytes(message_bytes, private_key)

    # Signs a JSON message using Ed25519 algorithm
    def __signMessageJSON(self, messageJSON: dict, private_key: ed25519.Ed25519PrivateKey):
        message_bytes = canonicalize_json(messageJSON)
        return self.__signMessageBytes(message_bytes, private_key)

    def signMessage(self, message: t.Any):
        private_key = self.__getPrivateKey()

        if isinstance(message, str):
            return self.__signMessageStr(message, private_key)

        elif isinstance(message, dict):
            return self.__signMessageJSON(message, private_key)

        elif isinstance(message, bytes):
            return self.__signMessageBytes(message, private_key)
        else:
            raise Exception("Error: Not supported instance")

    def getPublicKeyBytes(self):
        return (
            self.__getPrivateKey()
            .public_key()
            .public_bytes(encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH)
        )


class Verifier:
    def __init__(self):
        return

    # verify message with signature and public key bytes
    def verifyMessage(self, signature_b64: bytes, message: t.Any, public_key_bytes: bytes = None) -> bool:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)

        if isinstance(message, str):
            return self.__verifyMessageStr(signature_b64, message, public_key)
        elif isinstance(message, dict):
            return self.__verifyMessageJSON(signature_b64, message, public_key)
        elif isinstance(message, bytes):
            return self.__verifyMessageBytes(signature_b64, message, public_key)
        else:
            raise Exception("Error: Not supported instance")

    # Verify a message in bytes using Ed25519 algorithm
    def __verifyMessageBytes(
        self, signature_b64: bytes, message_bytes: bytes, public_key: ed25519.Ed25519PublicKey
    ) -> bool:
        try:
            signature = b64decode(signature_b64)
            public_key.verify(signature, message_bytes)
        except Exception:
            return False

        return True

    # Verify a string message using Ed25519 algorithm
    def __verifyMessageStr(self, signature_b64: bytes, message: str, public_key: ed25519.Ed25519PublicKey) -> bool:
        message_bytes = bytes(message, "utf8")
        return self.__verifyMessageBytes(signature_b64, message_bytes, public_key)

    # Verify a JSON message using Ed25519 algorithm
    def __verifyMessageJSON(
        self, signature_b64: bytes, messageJSON: dict, public_key: ed25519.Ed25519PublicKey
    ) -> bool:
        message_bytes = canonicalize_json(messageJSON)
        return self.__verifyMessageBytes(signature_b64, message_bytes, public_key)

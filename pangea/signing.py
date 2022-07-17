# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import os
from base64 import b64decode, b64encode
from os.path import exists

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .services.audit_util import canonicalize_json


class Signing:
    __private_key_file = ""
    __public_key_file = ""
    __private_key = None
    __public_key = None
    __private_key_cache = False
    __public_key_cache = False
    __overwrite_keys_if_exists = False
    __hash_message = False

    def __init__(
        self, generate_keys: bool = True, overwrite_keys_if_exists: bool = False, hash_message: bool = False
    ) -> None:
        self.generate_keys = generate_keys
        self.__hash_message = hash_message
        self.__overwrite_keys_if_exists = overwrite_keys_if_exists

        self.__private_key_file = os.getenv("PANGEA_AUDIT_PRIVATE_KEY_FILENAME")
        self.__public_key_file = os.getenv("PANGEA_AUDIT_PUBLIC_KEY_FILENAME")

        if self.generate_keys:
            self.generateKeys(overwrite_keys_if_exists)

    # Generates key pairs, storing in local disk.
    def generateKeys(self, overwrite_if_exists: bool):
        if not exists(self.__private_key_file) or not exists(self.__public_key_file) or overwrite_if_exists:
            try:
                private_key = ed25519.Ed25519PrivateKey.generate()
                private_bytes = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )

                with open(self.__private_key_file, "wb") as file:
                    file.write(private_bytes)

                self.__private_key_cache = False
            except Exception:
                raise Exception("Error: Failed generating private key.")

            try:
                public_key = private_key.public_key()
                public_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH
                )

                with open(self.__public_key_file, "wb") as file:
                    file.write(public_bytes)

                self.__public_key_cache = False
            except Exception:
                raise Exception("Error: Failed generating public key.")

    # Returns the private key
    def getPrivateKey(self):
        if not self.__private_key_cache:
            try:
                self.generateKeys(self.__overwrite_keys_if_exists)
                with open(self.__private_key_file, "rb") as file:
                    private_bytes = file.read()

                self.__private_key = serialization.load_pem_private_key(private_bytes, None)
            except Exception:
                raise Exception("Error: Failed loading private key.")

            if not isinstance(self.__private_key, ed25519.Ed25519PrivateKey):
                raise Exception("Private key is not using Ed25519 algorithm.")

        self.__private_key_cache = True
        return self.__private_key

    # Returns the public key
    def getPublicKey(self):
        if not self.__public_key_cache:
            try:
                with open(self.__public_key_file, "rb") as file:
                    public_bytes = file.read()

                self.__public_key = serialization.load_ssh_public_key(public_bytes)
            except Exception:
                raise Exception("Error: Failed loading public key.")

            if not isinstance(self.__public_key, ed25519.Ed25519PublicKey):
                raise Exception("Public key is not using Ed25519 algorithm.")

        self.__public_key_cache = True
        return self.__public_key

    # Signs a string message using Ed25519 algorithm
    def signMessageStr(self, message: str):
        message_bytes = bytes(message, "utf8")
        return self.signMessageBytes(message_bytes)

    # Signs a message in bytes using Ed25519 algorithm
    def signMessageBytes(self, message_bytes: bytes):
        private_key = self.getPrivateKey()
        try:
            if self.__hash_message:
                digest = hashes.Hash(hashes.SHA256())
                digest.update(message_bytes)
                message_bytes = digest.finalize()
            signature = private_key.sign(message_bytes)
            signature_b64 = b64encode(signature).decode("ascii")
        except Exception:
            return None

        return signature_b64

    # Signs a JSON message using Ed25519 algorithm
    def signMessageJSON(self, messageJSON: dict):
        message_bytes = canonicalize_json(messageJSON)
        return self.signMessageBytes(message_bytes)

    # Verify a string message using Ed25519 algorithm
    def verifyMessageStr(self, signature_b64: bytes, message: str) -> bool:
        message_bytes = bytes(message, "utf8")
        return self.verifyMessageBytes(signature_b64, message_bytes)

    # Verify a message in bytes using Ed25519 algorithm
    def verifyMessageBytes(self, signature_b64: bytes, message_bytes: bytes) -> bool:
        public_key = self.getPublicKey()
        try:
            if self.__hash_message:
                digest = hashes.Hash(hashes.SHA256())
                digest.update(message_bytes)
                message_bytes = digest.finalize()
            signature = b64decode(signature_b64)
            public_key.verify(signature, message_bytes)
        except Exception:
            return False

        return True

    # Verify a JSON message using Ed25519 algorithm
    def verifyMessageJSON(self, signature_b64: bytes, messageJSON: dict) -> bool:
        message_bytes = canonicalize_json(messageJSON)
        return self.verifyMessageBytes(signature_b64, message_bytes)

# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import os
from base64 import b64encode, b64decode
from os.path import exists
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from .services.audit_util import canonicalize_json

private_key_filename = os.getenv("PRIVATE_KEY")
public_key_filename = os.getenv("PUBLIC_KEY")

class Signing:
    __private_key_filename = private_key_filename
    __public_key_filename = public_key_filename
    __hash_message = False

    def __init__(self, generate_keys: bool = True, overwrite_keys_if_exists: bool =  False, hash_message: bool = False) -> None:
        self.generate_keys = generate_keys
        self.__hash_message = hash_message

        if self.generate_keys == True:
            self.generateKeys(overwrite_keys_if_exists)

    # Generates key pairs, storing in local disk.
    def generateKeys(self, overwrite_if_exists: bool):
        if not exists(self.__private_key_filename) or not exists(self.__public_key_filename) or overwrite_if_exists:
            try:
                private_key = ed25519.Ed25519PrivateKey.generate()
                private_bytes = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())

                with open(self.__private_key_filename, "wb") as file:
                    file.write(private_bytes)

            except Exception:
                raise Exception(f"Error: Failed generating private key.")

            try:
                public_key = private_key.public_key()
                public_bytes = public_key.public_bytes(encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH)

                with open(self.__public_key_filename, "wb") as file:
                    file.write(public_bytes)

            except Exception:
                raise Exception(f"Error: Failed generating public key.")

    # Returns the private key
    def getPrivateKey(self):
        try:
            with open(self.__private_key_filename, "rb") as file:
                private_bytes = file.read()
                
            private_key = serialization.load_pem_private_key(private_bytes, None)
        except Exception:
            raise Exception(f"Error: Failed loading private key.") 

        return private_key

    # Returns the public key
    def getPublicKey(self):
        try:
            with open(self.__public_key_filename, "rb") as file:
                public_bytes = file.read()

            public_key = serialization.load_ssh_public_key(public_bytes)           
        except Exception:
            raise Exception(f"Error: Failed loading public key.") 

        return public_key

    # Signs a string message using Ed25519 algorithm
    def signMessageStr(self, message: str):
        try:
            message_bytes = bytes(message, "utf8")
            return self.signMessageBytes(message_bytes)
        except Exception:
            return None

    # Signs a message in bytes using Ed25519 algorithm
    def signMessageBytes(self, message_bytes: bytes):
        try:
            private_key = self.getPrivateKey()
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
        try:
            message_bytes = canonicalize_json(messageJSON)
            signature_b64 = self.signMessageBytes(message_bytes)
        except Exception:
            return None

        return signature_b64

    # Verify a string message using Ed25519 algorithm
    def verifyMessageStr(self, signature_b64: bytes, message: str) -> bool:
        try:
            message_bytes = bytes(message, "utf8")
            return self.verifyMessageBytes(signature_b64, message_bytes)            
        except Exception:
            return False

    # Verify a message in bytes using Ed25519 algorithm
    def verifyMessageBytes(self, signature_b64: bytes, message_bytes: bytes) -> bool:
        try:
            public_key = self.getPublicKey()
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
        try:
            message_bytes = canonicalize_json(messageJSON)
            return self.verifyMessageBytes(signature_b64, message_bytes)
        except Exception:
            return False
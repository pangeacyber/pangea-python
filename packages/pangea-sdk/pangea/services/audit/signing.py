# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from cryptography import exceptions
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes

from pangea.exceptions import PangeaException
from pangea.services.audit.util import b64decode, b64decode_ascii, b64encode_ascii
from pangea.services.vault.models.asymmetric import AsymmetricKeySigningAlgorithm


class AlgorithmSigner(ABC):
    def __init__(self, private_key: PrivateKeyTypes):
        self.private_key = private_key

    @abstractmethod
    def sign(self, message: bytes) -> str:
        pass

    @abstractmethod
    def get_public_key_PEM(self) -> str:
        pass

    @abstractmethod
    def get_algorithm(self) -> str:
        pass


class ED25519Signer(AlgorithmSigner):
    def sign(self, message: bytes) -> str:
        signature = self.private_key.sign(message)  # type: ignore[call-arg, union-attr]
        return b64encode_ascii(signature)

    def get_public_key_PEM(self) -> str:
        return (
            self.private_key.public_key()
            .public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode("utf-8")
        )

    def get_algorithm(self) -> str:
        return AsymmetricKeySigningAlgorithm.ED25519.value


signers = {
    ed25519.Ed25519PrivateKey: ED25519Signer,
}


class Signer:
    private_key_file: str
    signer: Optional[AlgorithmSigner] = None

    def __init__(self, private_key_file: str):
        self.private_key_file = private_key_file

    def sign(self, message: bytes) -> str:
        self._load_signer()
        return self.signer.sign(message=message)  # type: ignore[union-attr]

    def get_public_key_PEM(self) -> str:
        self._load_signer()
        return self.signer.get_public_key_PEM()  # type: ignore[union-attr]

    def get_algorithm(self) -> str:
        self._load_signer()
        return self.signer.get_algorithm()  # type: ignore[union-attr]

    def _load_signer(self):
        if self.signer is not None:
            return

        if self.private_key_file:
            try:
                with open(self.private_key_file, "rb") as file:
                    file_bytes = file.read()
            except FileNotFoundError:
                raise Exception(f"Error: Failed opening private key file {self.private_key_file}")

            privkey = self._decode_private_key(file_bytes)
            for cls, signer in signers.items():
                if isinstance(privkey, cls):
                    self.signer = signer(privkey)
                    return

            raise PangeaException(f"Private key is not supported: {type(privkey)}.")

        raise PangeaException("Must pass a valid private key file name.")

    def _decode_private_key(self, private_key: bytes):
        """Parse a private key in PEM or ssh format"""

        for func in (serialization.load_pem_private_key, serialization.load_ssh_private_key):
            try:
                return func(private_key, None)
            except exceptions.UnsupportedAlgorithm as e:
                raise e
            except ValueError:
                pass

        raise PangeaException("Unsupported key")


class AlgorithmVerifier(ABC):
    def __init__(self, public_key: PublicKeyTypes):
        self.public_key = public_key

    @abstractmethod
    def verify(self, message: bytes, signature: bytes) -> bool:
        pass


class ED25519Verifier(AlgorithmVerifier):
    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self.public_key.verify(signature, message)  # type: ignore[call-arg,union-attr]
            return True
        except exceptions.InvalidSignature:
            return False


verifiers = {
    ed25519.Ed25519PublicKey: ED25519Verifier,
}


class Verifier:
    # verify message with signature and public key bytes
    def verify_signature(
        self, signature_b64: str, message_bytes: bytes, public_key_input: Optional[str] = None
    ) -> Optional[bool]:
        if self._has_header(public_key_input):  # type: ignore[arg-type]
            pubkey = self._decode_public_key(bytes(public_key_input, "utf-8"))  # type: ignore[arg-type]
        else:
            # To make backward compatible with original public keys send encoded bytes in base64
            public_key_bytes = b64decode_ascii(public_key_input)  # type: ignore[arg-type]
            pubkey = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes[-32:])

        signature_bytes = b64decode(signature_b64)
        for cls, verifier in verifiers.items():
            if isinstance(pubkey, cls):
                return verifier(pubkey).verify(message_bytes, signature_bytes)
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

    def _has_header(self, key: str) -> bool:
        return key.startswith("----") or key.startswith("ssh-")

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from pangea.services.vault.models.common import ExportEncryptionAlgorithm
from pangea.services.vault.models.symmetric import SymmetricKeyEncryptionAlgorithm

if TYPE_CHECKING:
    from pangea.services.vault.models.common import ExportResult


def generate_key_pair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    # Generate a 4096-bit RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # Extract the public key from the private key
    public_key = private_key.public_key()
    return private_key, public_key


def decrypt_sha512(private_key: rsa.RSAPrivateKey, encrypted_message: bytes) -> bytes:
    # Decrypt the message using the private key and OAEP padding
    return private_key.decrypt(
        encrypted_message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA512()), algorithm=hashes.SHA512(), label=None),
    )


def encrypt_sha512(public_key: rsa.RSAPublicKey, message: bytes) -> bytes:
    # Encrypt the message using the public key and OAEP padding
    return public_key.encrypt(
        message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA512()), algorithm=hashes.SHA512(), label=None)
    )


def private_key_to_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    # Serialize private key to PEM format
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(public_key: rsa.RSAPublicKey) -> bytes:
    # Serialize public key to PEM format
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


_AES_GCM_IV_SIZE = 12
"""Standard nonce size for GCM."""

_KEY_LENGTH = 32
"""AES-256 key length in bytes."""


def kem_decrypt(
    private_key: rsa.RSAPrivateKey,
    iv: bytes,
    ciphertext: bytes,
    symmetric_algorithm: str,
    asymmetric_algorithm: str,
    encrypted_salt: bytes,
    password: str,
    iteration_count: int,
    hash_algorithm: str,
) -> str:
    if symmetric_algorithm.casefold() != SymmetricKeyEncryptionAlgorithm.AES_GCM_256.value.casefold():
        raise NotImplementedError(f"Unsupported symmetric algorithm: {symmetric_algorithm}")

    if asymmetric_algorithm != ExportEncryptionAlgorithm.RSA_NO_PADDING_4096_KEM:
        raise NotImplementedError(f"Unsupported asymmetric algorithm: {asymmetric_algorithm}")

    if hash_algorithm.casefold() != "SHA512".casefold():
        raise NotImplementedError(f"Unsupported hash algorithm: {hash_algorithm}")

    # No-padding RSA decryption.
    n = private_key.private_numbers().public_numbers.n
    salt = pow(
        int.from_bytes(encrypted_salt, byteorder="big"),
        private_key.private_numbers().d,
        n,
    ).to_bytes(n.bit_length() // 8, byteorder="big")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(), length=_KEY_LENGTH, salt=salt, iterations=iteration_count, backend=default_backend()
    )
    symmetric_key = kdf.derive(password.encode("utf-8"))

    decrypted = AESGCM(symmetric_key).decrypt(nonce=iv, data=ciphertext, associated_data=None)

    return decrypted.decode("ascii")


def kem_decrypt_export_result(*, result: ExportResult, password: str, private_key: rsa.RSAPrivateKey) -> str:
    """Decrypt the exported result of a KEM operation."""
    cipher_encoded = result.private_key or result.key
    if not cipher_encoded:
        raise TypeError("`private_key` or `key` should be set.")

    assert result.encrypted_salt
    assert result.symmetric_algorithm
    assert result.asymmetric_algorithm
    assert result.iteration_count
    assert result.hash_algorithm

    cipher_with_iv = base64.b64decode(cipher_encoded)
    encrypted_salt = base64.b64decode(result.encrypted_salt)

    iv = cipher_with_iv[:_AES_GCM_IV_SIZE]
    cipher = cipher_with_iv[_AES_GCM_IV_SIZE:]

    return kem_decrypt(
        private_key=private_key,
        iv=iv,
        ciphertext=cipher,
        password=password,
        encrypted_salt=encrypted_salt,
        symmetric_algorithm=result.symmetric_algorithm,
        asymmetric_algorithm=result.asymmetric_algorithm,
        iteration_count=result.iteration_count,
        hash_algorithm=result.hash_algorithm,
    )

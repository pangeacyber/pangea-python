from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


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

# This example demonstrates how to use Vault's format-preserving encryption (FPE)
# to encrypt and decrypt text without changing its length.

import os
from secrets import token_hex

from pangea.config import PangeaConfig
from pangea.services import Vault
from pangea.services.vault.models.common import (
    KeyPurpose,
    SymmetricAlgorithm,
    TransformAlphabet,
)


def main() -> None:
    # Set up a Pangea Vault client.
    token = os.getenv("PANGEA_VAULT_TOKEN")
    assert token
    domain = os.getenv("PANGEA_DOMAIN")
    assert domain
    config = PangeaConfig(domain=domain)
    vault = Vault(token, config=config)

    # Plain text that we'll encrypt.
    plain_text = "123-4567-8901"

    # Optional tweak string.
    tweak = "MTIzMTIzMT=="

    # Generate an encryption key.
    generated = vault.symmetric_generate(
        algorithm=SymmetricAlgorithm.AES256_FF3_1_BETA,
        purpose=KeyPurpose.FPE,
        name=f"python-fpe-example-{token_hex(8)}",
    )
    assert generated.result
    key_id = generated.result.id

    # Encrypt the plain text.
    encrypted = vault.encrypt_transform(
        id=key_id,
        plain_text=plain_text,
        tweak=tweak,
        alphabet=TransformAlphabet.NUMERIC,
    )
    assert encrypted.result
    encrypted_text = encrypted.result.cipher_text
    print(f"Plain text: {plain_text}. Encrypted text: {encrypted_text}.")

    # Decrypt the result to get back the text we started with.
    decrypted = vault.decrypt_transform(
        id=key_id,
        cipher_text=encrypted_text,
        tweak=tweak,
        alphabet=TransformAlphabet.NUMERIC,
    )
    assert decrypted.result
    decrypted_text = decrypted.result.plain_text
    print(f"Original text: {plain_text}. Decrypted text: {decrypted_text}.")


if __name__ == "__main__":
    main()

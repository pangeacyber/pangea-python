# This example demonstrates how to use Vault's format-preserving encryption (FPE)
# to encrypt and decrypt text without changing its length.

import asyncio
import os
from secrets import token_hex

from pangea.asyncio.services import VaultAsync
from pangea.config import PangeaConfig
from pangea.services.vault.models.common import ItemType, TransformAlphabet
from pangea.services.vault.models.symmetric import (
    SymmetricKeyFpeAlgorithm,
    SymmetricKeyPurpose,
)


async def main() -> None:
    # Set up a Pangea Vault client.
    token = os.getenv("PANGEA_VAULT_TOKEN")
    assert token
    url_template = os.getenv("PANGEA_URL_TEMPLATE")
    assert url_template
    config = PangeaConfig(base_url_template=url_template)
    vault = VaultAsync(token, config=config)

    # Plain text that we'll encrypt.
    plain_text = "123-4567-8901"

    # Optional tweak string.
    tweak = "MTIzMTIzMT=="

    # Generate an encryption key.
    generated = await vault.generate_key(
        key_type=ItemType.SYMMETRIC_KEY,
        algorithm=SymmetricKeyFpeAlgorithm.AES_FF3_1_256_BETA,
        purpose=SymmetricKeyPurpose.FPE,
        name=f"python-fpe-example-{token_hex(8)}",
    )
    assert generated.result
    key_id = generated.result.id

    # Encrypt the plain text.
    encrypted = await vault.encrypt_transform(
        key_id,
        plain_text=plain_text,
        tweak=tweak,
        alphabet=TransformAlphabet.NUMERIC,
    )
    assert encrypted.result
    encrypted_text = encrypted.result.cipher_text
    print(f"Plain text: {plain_text}. Encrypted text: {encrypted_text}.")

    # Decrypt the result to get back the text we started with.
    decrypted = await vault.decrypt_transform(
        key_id,
        cipher_text=encrypted_text,
        tweak=tweak,
        alphabet=TransformAlphabet.NUMERIC,
    )
    assert decrypted.result
    decrypted_text = decrypted.result.plain_text
    print(f"Original text: {plain_text}. Decrypted text: {decrypted_text}.")


if __name__ == "__main__":
    asyncio.run(main())

import asyncio
import os
import time

import pangea.exceptions as pe
from pangea.asyncio.services import VaultAsync
from pangea.config import PangeaConfig
from pangea.services.vault.models.common import ItemType
from pangea.services.vault.models.symmetric import (
    SymmetricKeyEncryptionAlgorithm,
    SymmetricKeyPurpose,
)
from pangea.utils import str2str_b64


async def main() -> None:
    token = os.getenv("PANGEA_VAULT_TOKEN", "")
    url_template = os.getenv("PANGEA_URL_TEMPLATE", "")
    config = PangeaConfig(base_url_template=url_template)
    vault = VaultAsync(token, config=config)

    try:
        # Set a unique name.
        name = f"Python encrypt example {int(time.time())}"

        # Create a symmetric key with the default parameters.
        create_response = await vault.generate_key(
            key_type=ItemType.SYMMETRIC_KEY,
            purpose=SymmetricKeyPurpose.ENCRYPTION,
            algorithm=SymmetricKeyEncryptionAlgorithm.AES_CFB_128,
            name=name,
        )
        assert create_response.result
        key_id = create_response.result.id

        # Encrypt a message.
        text = "hello world"
        msg = str2str_b64(text)
        print(f"Encript text: {text}")
        encrypt_response = await vault.encrypt(key_id, msg)
        assert encrypt_response.result
        cipher_text = encrypt_response.result.cipher_text
        print(f"Cipher text: {cipher_text}")

        # Decrypt the message.
        print("Decrypting...")
        decrypt_response = await vault.decrypt(key_id, cipher_text)
        assert decrypt_response.result
        plain_text = decrypt_response.result.plain_text

        if plain_text == msg:
            print("Text encrypted and decrypted successfully")
        else:
            print("Encrypted/decrypted message is not equal to original message")

    except pe.PangeaAPIException as e:
        print(f"Vault Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")

    await vault.close()


if __name__ == "__main__":
    asyncio.run(main())

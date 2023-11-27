import asyncio
import os
import time

import pangea.exceptions as pe
from pangea.asyncio.services import VaultAsync
from pangea.config import PangeaConfig
from pangea.services.vault.models.common import KeyPurpose
from pangea.services.vault.models.symmetric import SymmetricAlgorithm
from pangea.utils import str2str_b64


async def main():
    token = os.getenv("PANGEA_VAULT_TOKEN")
    domain = os.getenv("PANGEA_DOMAIN")
    config = PangeaConfig(domain=domain)
    vault = VaultAsync(token, config=config)

    try:
        # Set a unique name.
        name = f"Python encrypt example {int(time.time())}"

        # Create a symmetric key with the default parameters.
        create_response = await vault.symmetric_generate(
            purpose=KeyPurpose.ENCRYPTION, algorithm=SymmetricAlgorithm.AES128_CFB, name=name
        )
        key_id = create_response.result.id

        # Encrypt a message.
        text = "hello world"
        msg = str2str_b64(text)
        print(f"Encript text: {text}")
        encrypt_response = await vault.encrypt(key_id, msg)
        cipher_text = encrypt_response.result.cipher_text
        print(f"Cipher text: {cipher_text}")

        # Decrypt the message.
        print("Decrypting...")
        decrypt_response = await vault.decrypt(key_id, cipher_text)
        plain_text = decrypt_response.result.plain_text

        if plain_text == msg:
            print("Text encrypted and decrypted succesfully")
        else:
            print("Encrypted/decrypted message is not equal to original message")

    except pe.PangeaAPIException as e:
        print(f"Vault Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")

    await vault.close()


if __name__ == "__main__":
    asyncio.run(main())

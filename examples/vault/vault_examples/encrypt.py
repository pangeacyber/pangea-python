import os
import time

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services.vault.models.common import KeyPurpose
from pangea.services.vault.models.symmetric import SymmetricAlgorithm
from pangea.services.vault.vault import Vault
from pangea.utils import str2str_b64


def main():
    token = os.getenv("PANGEA_VAULT_TOKEN")
    domain = os.getenv("PANGEA_DOMAIN")
    config = PangeaConfig(domain=domain)
    vault = Vault(token, config=config)

    try:
        # name should be unique
        name = f"Python encrypt example {int(time.time())}"

        # create a symmetric key with Pangea-provided material and default parameters
        create_response = vault.symmetric_generate(
            purpose=KeyPurpose.ENCRYPTION, algorithm=SymmetricAlgorithm.AES128_CFB, name=name
        )
        key_id = create_response.result.id

        # encrypt a message
        text = "hello world"
        msg = str2str_b64(text)
        print(f"Encript text: {text}")
        encrypt_response = vault.encrypt(key_id, msg)
        cipher_text = encrypt_response.result.cipher_text
        print(f"Cipher text: {cipher_text}")

        # decrypt it
        print("Decrypting...")
        decrypt_response = vault.decrypt(key_id, cipher_text)
        plain_text = decrypt_response.result.plain_text

        if plain_text == msg:
            print("Text encrypted and decrypted succesfully")
        else:
            print("Encrypted/decrypted message is not equal to original message")

    except pe.PangeaAPIException as e:
        print(f"Vault Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

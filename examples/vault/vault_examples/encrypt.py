import os
from secrets import token_hex

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services.vault.models.common import KeyPurpose
from pangea.services.vault.models.symmetric import SymmetricAlgorithm
from pangea.services.vault.vault import Vault
from pangea.utils import str2str_b64


def main() -> None:
    token = os.getenv("PANGEA_VAULT_TOKEN")
    domain = os.getenv("PANGEA_DOMAIN")
    assert domain
    config = PangeaConfig(domain=domain)
    vault = Vault(token, config=config)

    try:
        # Set a unique name.
        name = f"Python encrypt example {token_hex(8)}"

        # Create a symmetric key with the default parameters.
        create_response = vault.symmetric_generate(
            purpose=KeyPurpose.ENCRYPTION, algorithm=SymmetricAlgorithm.AES128_CFB, name=name
        )
        assert create_response.result
        key_id = create_response.result.id

        # Encrypt a message.
        text = "hello world"
        msg = str2str_b64(text)
        print(f"Encrypt text: {text}")
        encrypt_response = vault.encrypt(key_id, msg)
        assert encrypt_response.result
        cipher_text = encrypt_response.result.cipher_text
        print(f"Cipher text: {cipher_text}")

        # Decrypt the message to verify it is the same as the original message.
        print("Decrypting...")
        decrypt_response = vault.decrypt(key_id, cipher_text)
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


if __name__ == "__main__":
    main()

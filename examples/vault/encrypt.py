import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services.vault.models.asymmetric import AsymmetricAlgorithm
from pangea.services.vault.models.common import KeyPurpose
from pangea.services.vault.vault import Vault
from pangea.utils import str2str_b64


def main():
    token = os.getenv("PANGEA_VAULT_TOKEN")
    domain = os.getenv("PANGEA_DOMAIN")
    config = PangeaConfig(domain=domain)
    vault = Vault(token, config=config)

    try:
        # create a symmetric key with Pangea-provided material and default parameters
        create_response = vault.symmetric_generate(
            purpose=KeyPurpose.ENCRYPTION, algorithm=AsymmetricAlgorithm.RSA, name="test key"
        )
        key_id = create_response.result.id

        # encrypt a message
        msg = str2str_b64("hello world")
        encrypt_response = vault.encrypt(key_id, msg)
        cipher_text = encrypt_response.result.cipher_text

        # decrypt it
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

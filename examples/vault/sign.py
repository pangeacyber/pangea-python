import os
import base64

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import Vault

token = os.getenv("PANGEA_VAULT_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
vault = Vault(token, config=config)


def main():
    try:

        # create an asymmetric key with Pangea-provided material and default parameters
        create_response = vault.create_asymmetric(name="test key")
        key_id = create_response.result.id

        # sign a message
        msg = base64.b64encode(b"hello world")
        sign_response = vault.sign(key_id, msg)
        signature = sign_response.result.signature

        # verify it
        verify_response = vault.verify(key_id, msg, signature)
        
        if verify_response.result.valid_signature:
            print("Signature verified succesfully")
        else:
            print("Invalid signature")

    except pe.PangeaAPIException as e:
        print(f"Vault Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

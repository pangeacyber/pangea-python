import base64
import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import Vault

token = os.getenv("PANGEA_VAULT_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
vault = Vault(token, config=config)


def main():
    try:
        secret_1 = "my first secret"
        secret_2 = "my second secret"

        # store a secret
        create_response = vault.store_secret(name="very secret", secret=secret_1)
        secret_id = create_response.result.id

        # rotate it
        vault.rotate_secret(secret_id, secret_2)

        # retrieve latest version
        retrieve_response = vault.get(secret_id)

        if retrieve_response.result.secret == secret_2:
            print("version 2 ok")
        else:
            print("version 2 is wrong")

        # retrieve version 1
        retrieve_response = vault.get(secret_id, version=1)

        if retrieve_response.result.secret == secret_1:
            print("version 1 ok")
        else:
            print("version 1 is wrong")

    except pe.PangeaAPIException as e:
        print(f"Vault Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

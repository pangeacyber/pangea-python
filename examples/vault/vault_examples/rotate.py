import os
import time

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import Vault


def main():
    token = os.getenv("PANGEA_VAULT_TOKEN")
    domain = os.getenv("PANGEA_DOMAIN")
    config = PangeaConfig(domain=domain)
    vault = Vault(token, config=config)

    try:
        secret_1 = "my first secret"
        secret_2 = "my second secret"
        # Set a unique name.
        name = f"Python secret example {int(time.time())}"

        # Store a secret.
        create_response = vault.secret_store(name=name, secret=secret_1)
        secret_id = create_response.result.id
        print(f"Created success. ID: {secret_id}")

        # Rotate the secret.
        vault.secret_rotate(secret_id, secret_2)

        # Retrieve the latest version.
        get_response = vault.get(secret_id)

        if get_response.result.current_version.secret == secret_2:
            print("version 2 ok")
        else:
            print("version 2 is wrong")

        # Retrieve version 1
        get_response = vault.get(secret_id, version=1)

        if get_response.result.versions[0].secret == secret_1:
            print("version 1 ok")
        else:
            print("version 1 is wrong")

    except pe.PangeaAPIException as e:
        print(f"Vault Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

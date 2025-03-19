from __future__ import annotations

import asyncio
import os
import time

import pangea.exceptions as pe
from pangea.asyncio.services import VaultAsync
from pangea.config import PangeaConfig


async def main():
    token = os.getenv("PANGEA_VAULT_TOKEN")
    url_template = os.getenv("PANGEA_URL_TEMPLATE")
    config = PangeaConfig(base_url_template=url_template)
    vault = VaultAsync(token, config=config)

    try:
        secret_1 = "my first secret"
        secret_2 = "my second secret"
        # Set a unique name.
        name = f"Python secret example {int(time.time())}"

        # Store a secret.
        create_response = await vault.store_secret(name=name, secret=secret_1)
        secret_id = create_response.result.id
        print(f"Created success. ID: {secret_id}")

        # Rotate the secret.
        await vault.rotate_secret(secret_id, secret_2)

        # Retrieve latest version of the secret.
        get_response = await vault.get(secret_id)

        if get_response.result.item_versions[0].secret == secret_2:
            print("version 2 ok")
        else:
            print("version 2 is wrong")

        # Retrieve version 1 of the secret.
        get_response = await vault.get(secret_id, version=1)

        if get_response.result.item_versions[0].secret == secret_1:
            print("version 1 ok")
        else:
            print("version 1 is wrong")

    except pe.PangeaAPIException as e:
        print(f"Vault Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")

    await vault.close()


if __name__ == "__main__":
    asyncio.run(main())

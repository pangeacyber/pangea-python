import asyncio
import os
import time

import pangea.exceptions as pe
from pangea.asyncio.services import VaultAsync
from pangea.config import PangeaConfig
from pangea.services.vault.models.asymmetric import (
    AsymmetricKeyPurpose,
    AsymmetricKeySigningAlgorithm,
)
from pangea.services.vault.models.common import ItemType
from pangea.utils import str2str_b64


async def main() -> None:
    token = os.getenv("PANGEA_VAULT_TOKEN", "")
    url_template = os.getenv("PANGEA_URL_TEMPLATE", "")
    config = PangeaConfig(base_url_template=url_template)
    vault = VaultAsync(token, config=config)

    try:
        # Set a unique name.
        name = f"Python sign example {int(time.time())}"

        # Create an asymmetric key with the default parameters.
        create_response = await vault.generate_key(
            key_type=ItemType.ASYMMETRIC_KEY,
            algorithm=AsymmetricKeySigningAlgorithm.ED25519,
            purpose=AsymmetricKeyPurpose.SIGNING,
            name=name,
        )
        assert create_response.result
        key_id = create_response.result.id

        # Sign a message.
        text = "hello world"
        msg = str2str_b64(text)
        print(f"text to sign: {text}")
        sign_response = await vault.sign(key_id, msg)
        assert sign_response.result
        signature = sign_response.result.signature
        print(f"Signature: {signature}")

        # Verify the message's signature.
        print("Verifying...")
        verify_response = await vault.verify(key_id, msg, signature)
        assert verify_response.result
        if verify_response.result.valid_signature:
            print("Signature verified succesfully")
        else:
            print("Invalid signature")

    except pe.PangeaAPIException as e:
        print(f"Vault Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")

    await vault.close()


if __name__ == "__main__":
    asyncio.run(main())

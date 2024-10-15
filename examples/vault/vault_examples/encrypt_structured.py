import os
from secrets import token_hex

from pangea.config import PangeaConfig
from pangea.services.vault.models.common import ItemType
from pangea.services.vault.models.symmetric import (
    SymmetricKeyEncryptionAlgorithm,
    SymmetricKeyPurpose,
)
from pangea.services.vault.vault import Vault


def main() -> None:
    token = os.getenv("PANGEA_VAULT_TOKEN")
    assert token

    domain = os.getenv("PANGEA_DOMAIN")
    assert domain

    config = PangeaConfig(domain)
    vault = Vault(token, config)

    # First create an encryption key, either from the Pangea Console or
    # programmatically as below.
    create_response = vault.generate_key(
        key_type=ItemType.SYMMETRIC_KEY,
        purpose=SymmetricKeyPurpose.ENCRYPTION,
        algorithm=SymmetricKeyEncryptionAlgorithm.AES_CFB_256,
        name=f"Python encrypt example {token_hex(8)}",
    )
    assert create_response.result
    encryption_key_id = create_response.result.id

    # Structured data that we'll encrypt.
    data = {"foo": [1, 2, "bar", "baz"], "some": "thing"}

    response = vault.encrypt_structured(encryption_key_id, data, "$.foo[2:4]")
    assert response.result
    print(f"Encrypted result: {response.result.structured_data}")


if __name__ == "__main__":
    main()

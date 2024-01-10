import os

from pangea.config import PangeaConfig
from pangea.services.vault.models.common import KeyPurpose
from pangea.services.vault.models.symmetric import SymmetricAlgorithm
from pangea.services.vault.vault import Vault


def main():
    token = os.getenv("PANGEA_VAULT_TOKEN")
    assert token

    domain = os.getenv("PANGEA_DOMAIN")
    assert domain

    config = PangeaConfig(domain)
    vault = Vault(token, config)

    # First create an encryption key, either from the Pangea Console or
    # programmatically as below.
    create_response = vault.symmetric_generate(
        purpose=KeyPurpose.ENCRYPTION, algorithm=SymmetricAlgorithm.AES256_CFB, name="any unique name"
    )
    encryption_key_id = create_response.result.id

    # Structured data that we'll encrypt.
    data = {
        "foo": [1, 2, "bar", "baz"],
        "some": "thing"
    }

    response = vault.encrypt_structured(encryption_key_id, data, "$.foo[2:4]")
    print(f"Encrypted result: {response.result.structured_data}")


if __name__ == "__main__":
    main()

from __future__ import annotations

import os
from secrets import token_hex

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.crypto import rsa
from pangea.services.vault.models.asymmetric import (
    AsymmetricKeyPurpose,
    AsymmetricKeySigningAlgorithm,
)
from pangea.services.vault.models.common import ExportEncryptionAlgorithm, ItemType
from pangea.services.vault.vault import Vault
from pangea.utils import str_b64_2bytes


def main() -> None:
    token = os.getenv("PANGEA_VAULT_TOKEN")
    assert token
    domain = os.getenv("PANGEA_DOMAIN")
    assert domain
    config = PangeaConfig(domain=domain)
    vault = Vault(token, config=config)

    try:
        # Set a unique name.
        name = f"Python export example {token_hex(8)}"

        # Create an asymmetric key that is exportable.
        create_response = vault.generate_key(
            key_type=ItemType.ASYMMETRIC_KEY,
            algorithm=AsymmetricKeySigningAlgorithm.ED25519,
            purpose=AsymmetricKeyPurpose.SIGNING,
            name=name,
            exportable=True,
        )

        assert create_response.result
        key_id = create_response.result.id

        # Export with no encryption.
        exp_resp = vault.export(item_id=key_id, version=1)
        assert exp_resp.result
        assert exp_resp.result.private_key
        assert exp_resp.result.public_key

        # Use keys in PEM
        print("Private key:\n", exp_resp.result.private_key)
        print("Public key:\n", exp_resp.result.public_key)

        # export with encryption
        # generate key pair to encrypt exported key
        rsa_priv_key, rsa_pub_key = rsa.generate_key_pair()
        rsa_pub_key_pem = rsa.public_key_to_pem(rsa_pub_key)

        # send export request with public key to encrypt exported key
        exp_encrypted_resp = vault.export(
            item_id=key_id,
            version=1,
            asymmetric_public_key=rsa_pub_key_pem.decode("utf8"),
            asymmetric_algorithm=ExportEncryptionAlgorithm.RSA4096_OAEP_SHA512,
        )

        assert exp_encrypted_resp.result
        assert exp_encrypted_resp.result.private_key
        assert exp_encrypted_resp.result.public_key

        # Decrypt exported key
        exp_priv_key_decoded = str_b64_2bytes(exp_encrypted_resp.result.private_key)
        exp_priv_key_pem = rsa.decrypt_sha512(rsa_priv_key, exp_priv_key_decoded)

        print("Private key:\n", exp_priv_key_pem.decode("ascii"))
        print("Public key: \n", exp_encrypted_resp.result.public_key)

    except pe.PangeaAPIException as e:
        print(f"Vault Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

import asyncio
import os
from secrets import token_hex

import pangea.crypto.rsa as rsa
import pangea.exceptions as pe
from pangea.asyncio.services import VaultAsync
from pangea.config import PangeaConfig
from pangea.services.vault.models.asymmetric import AsymmetricAlgorithm
from pangea.services.vault.models.common import ExportEncryptionAlgorithm, KeyPurpose
from pangea.utils import str_b64_2bytes


async def main():
    token = os.getenv("PANGEA_VAULT_TOKEN")
    domain = os.getenv("PANGEA_DOMAIN")
    config = PangeaConfig(domain=domain)
    vault = VaultAsync(token, config=config)

    try:
        # Set a unique name.
        name = f"Python export example {token_hex(8)}"

        # Create an asymmetric key with exportable set to true
        create_response = await vault.asymmetric_generate(
            algorithm=AsymmetricAlgorithm.Ed25519, purpose=KeyPurpose.SIGNING, name=name, exportable=True
        )

        assert create_response.result
        key_id = create_response.result.id

        # export with no encryption
        exp_resp = await vault.export(id=key_id, version=1)
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
        exp_encrypted_resp = await vault.export(
            id=key_id,
            version=1,
            encryption_key=rsa_pub_key_pem,
            encryption_algorithm=ExportEncryptionAlgorithm.RSA4096_OAEP_SHA512,
        )

        assert exp_encrypted_resp.result
        assert exp_encrypted_resp.result.private_key
        assert exp_encrypted_resp.result.public_key

        # Decrypt exported key
        exp_pub_key_decoded = str_b64_2bytes(exp_encrypted_resp.result.public_key)
        exp_priv_key_decoded = str_b64_2bytes(exp_encrypted_resp.result.private_key)
        exp_priv_key_pem = rsa.decrypt_sha512(rsa_priv_key, exp_priv_key_decoded)
        exp_pub_key_pem = rsa.decrypt_sha512(rsa_priv_key, exp_pub_key_decoded)

        print("Private key:\n", exp_priv_key_pem.decode("ascii"))
        print("Public key: \n", exp_pub_key_pem.decode("ascii"))

    except pe.PangeaAPIException as e:
        print(f"Vault Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")

    await vault.close()


if __name__ == "__main__":
    asyncio.run(main())

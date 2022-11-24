# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from typing import Dict, List, Optional

from pangea.response import PangeaResponse
from pangea.services.base import ServiceBase
from pangea.services.vault.models.asymmetric import *
from pangea.services.vault.models.secret import *
from pangea.services.vault.models.symmetric import *


class Vault(ServiceBase):
    """Vault service client.

    Provides methods to interact with the [Pangea Vault Service](https://pangea.cloud/docs/api/vault).

    The following information is needed:
        PANGEA_VAULT_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services.vault import Vault

        PANGEA_VAULT_TOKEN = os.getenv("PANGEA_VAULT_TOKEN")
        vault_config = PangeaConfig(domain="pangea.cloud")

        # Setup Pangea Vault service
        vault = Vault(token=PANGEA_VAULT_TOKEN, config=audit_config)
    """

    service_name: str = "vault"
    version: str = "v1"

    def __init__(
        self,
        token,
        config=None,
    ):
        super().__init__(token, config)

    # Create endpoints
    def create_secret(
        self,
        name: Optional[str] = None,
        folder: Optional[str] = None,
        metadata: Optional[Medatada] = None,
        tags: Optional[Tags] = None,
        auto_rotate: Optional[bool] = None,
        rotation_policy: Optional[str] = None,
        retain_previous_version: Optional[bool] = None,
        expiration: Optional[datetime.datetime] = None,
    ) -> PangeaResponse[CreateSecretResult]:
        input = CreateCommonRequest(
            name=name,
            folder=folder,
            metadata=metadata,
            tags=tags,
            auto_rotate=auto_rotate,
            rotation_policy=rotation_policy,
            retain_previous_version=retain_previous_version,
            expiration=expiration,
        )
        response = self.request.post("secret/create", data=input.json(exclude_none=True))
        response.result = CreateSecretResult(**response.raw_result)
        return response

    def create_symmetric(
        self,
        algorithm: KeyAlgorithm,
        managed: Optional[bool] = None,
        store: Optional[bool] = None,
        name: Optional[str] = None,
        folder: Optional[str] = None,
        metadata: Optional[Medatada] = None,
        tags: Optional[Tags] = None,
        auto_rotate: Optional[bool] = None,
        rotation_policy: Optional[str] = None,
        retain_previous_version: Optional[bool] = None,
        expiration: Optional[datetime.datetime] = None,
    ) -> PangeaResponse[CreateKeyResult]:
        input = CreateKeyRequest(
            algorithm=algorithm,
            managed=managed,
            store=store,
            name=name,
            type="symmetric_key",
            folder=folder,
            metadata=metadata,
            tags=tags,
            auto_rotate=auto_rotate,
            rotation_policy=rotation_policy,
            retain_previous_version=retain_previous_version,
            expiration=expiration,
        )
        response = self.request.post("key/create", data=input.json(exclude_none=True))
        response.result = CreateKeyResult(**response.raw_result)
        return response

    def create_asymmetric(
        self,
        algorithm: KeyAlgorithm,
        purpose: KeyPairPurpose,
        managed: Optional[bool] = None,
        store: Optional[bool] = None,
        name: Optional[str] = None,
        folder: Optional[str] = None,
        metadata: Optional[Medatada] = None,
        tags: Optional[Tags] = None,
        auto_rotate: Optional[bool] = None,
        rotation_policy: Optional[str] = None,
        retain_previous_version: Optional[bool] = None,
        expiration: Optional[datetime.datetime] = None,
    ) -> PangeaResponse[CreateKeyPairResult]:
        input = CreateKeyPairRequest(
            algorithm=algorithm,
            purpose=purpose,
            managed=managed,
            store=store,
            name=name,
            type="asymmetric_key",
            folder=folder,
            metadata=metadata,
            tags=tags,
            auto_rotate=auto_rotate,
            rotation_policy=rotation_policy,
            retain_previous_version=retain_previous_version,
            expiration=expiration,
        )
        response = self.request.post("key/create", data=input.json(exclude_none=True))
        response.result = CreateKeyPairResult(**response.raw_result)
        return response

    # Store endpoints
    def store_asymmetric(
        self,
        algorithm: KeyPairAlgorithm,
        purpose: KeyPairPurpose,
        public_key: EncodedPublicKey,
        private_key: EncodedPrivateKey,
        name: Optional[str] = None,
        folder: Optional[str] = None,
        metadata: Optional[Medatada] = None,
        tags: Optional[Tags] = None,
        managed: Optional[bool] = None,
        rotation_policy: Optional[str] = None,
        auto_rotate: Optional[bool] = None,
        retain_previous_version: Optional[bool] = None,
        expiration: Optional[datetime.datetime] = None,
    ) -> PangeaResponse[StoreKeyPairResult]:
        input = StoreKeyPairRequest(
            type=ItemType.ASYMMETRIC_KEY,
            algorithm=algorithm,
            purpose=purpose,
            public_key=public_key,
            private_key=private_key,
            name=name,
            folder=folder,
            metadata=metadata,
            tags=tags,
            managed=managed,
            rotation_policy=rotation_policy,
            auto_rotate=auto_rotate,
            retain_previous_version=retain_previous_version,
            expiration=expiration,
        )
        response = self.request.post("store", data=input.json(exclude_none=True))
        response.result = StoreKeyPairResult(**response.raw_result)
        return response

    def store_symmetric(
        self,
        algorithm: KeyAlgorithm,
        key: str,
        name: Optional[str] = None,
        folder: Optional[str] = None,
        metadata: Optional[Medatada] = None,
        tags: Optional[Tags] = None,
        managed: Optional[bool] = None,
        rotation_policy: Optional[str] = None,
        auto_rotate: Optional[bool] = None,
        retain_previous_version: Optional[bool] = None,
        expiration: Optional[datetime.datetime] = None,
    ) -> PangeaResponse[StoreKeyResult]:
        input = StoreKeyRequest(
            type=ItemType.SYMMETRIC_KEY,
            algorithm=algorithm,
            key=key,
            name=name,
            folder=folder,
            metadata=metadata,
            tags=tags,
            managed=managed,
            rotation_policy=rotation_policy,
            auto_rotate=auto_rotate,
            retain_previous_version=retain_previous_version,
            expiration=expiration,
        )
        response = self.request.post("store", data=input.json(exclude_none=True))
        response.result = StoreKeyResult(**response.raw_result)
        return response

    def store_secret(
        self,
        secret: str,
        name: Optional[str] = None,
        folder: Optional[str] = None,
        metadata: Optional[Medatada] = None,
        tags: Optional[Tags] = None,
        rotation_policy: Optional[str] = None,
        auto_rotate: Optional[bool] = None,
        retain_previous_version: Optional[bool] = None,
        expiration: Optional[datetime.datetime] = None,
    ) -> PangeaResponse[StoreSecretResult]:
        input = StoreSecretRequest(
            type=ItemType.SECRET,
            secret=secret,
            name=name,
            folder=folder,
            metadata=metadata,
            tags=tags,
            rotation_policy=rotation_policy,
            auto_rotate=auto_rotate,
            retain_previous_version=retain_previous_version,
            expiration=expiration,
        )
        response = self.request.post("store", data=input.json(exclude_none=True))
        response.result = StoreSecretResult(**response.raw_result)
        return response

    # Retrieve endpoint
    def retrieve(
        self,
        id: str,
        version: Optional[int] = None,
        verbose: Optional[bool] = None,
    ) -> PangeaResponse[RetrieveGenericResult]:
        input = RetrieveRequest(
            id=id,
            version=version,
            verbose=verbose,
        )
        response = self.request.post("get", data=input.json(exclude_none=True))
        response.result = RetrieveGenericResult(**response.raw_result)
        return response

    # Revoke endpoint
    def revoke(self, id: str) -> PangeaResponse[RevokeResult]:
        input = RevokeRequest(
            id=id,
        )
        response = self.request.post("revoke", data=input.json(exclude_none=True))
        response.result = RevokeResult(**response.raw_result)
        return response

    # Rotate endpoints
    def rotate_secret(self, id: str) -> PangeaResponse[RotateSecretResult]:
        input = RotateCommonRequest(id=id)
        response = self.request.post("secret/rotate", data=input.json(exclude_none=True))
        response.result = RotateSecretResult(**response.raw_result)
        return response

    def rotate_key(self, id: str) -> PangeaResponse[RotateGenericKeyResult]:
        input = RotateCommonRequest(id=id)
        response = self.request.post("key/rotate", data=input.json(exclude_none=True))
        response.result = RotateGenericKeyResult(**response.raw_result)
        return response

    # Encrypt/Decrypt
    def encrypt(self, id: str, plain_text: str) -> PangeaResponse[EncryptResult]:
        input = EncryptRequest(id=id, plain_text=plain_text)
        response = self.request.post("key/encrypt", data=input.json(exclude_none=True))
        response.result = EncryptResult(**response.raw_result)
        return response

    def decrypt(
        self, id: str, cipher_text: str, version: Optional[int] = None, allow_revoked: Optional[bool] = None
    ) -> PangeaResponse[DecryptResult]:
        input = DecryptRequest(id=id, cipher_text=cipher_text, version=version, allow_revoked=allow_revoked)
        response = self.request.post("key/decrypt", data=input.json(exclude_none=True))
        response.result = DecryptResult(**response.raw_result)
        return response

    # Sign/Verify endpoints
    def sign(self, id: str, message: str) -> PangeaResponse[SignResult]:
        input = SignRequest(id=id, message=message)
        response = self.request.post("key/sign", data=input.json(exclude_none=True))
        response.result = SignResult(**response.raw_result)
        return response

    def verify(
        self, id: str, message: str, signature: str, version: Optional[int] = None, allow_revoked: Optional[bool] = None
    ) -> PangeaResponse[VerifyResult]:
        input = VerifyRequest(
            id=id,
            message=message,
            signature=signature,
            version=version,
            allow_revoked=allow_revoked,
        )
        response = self.request.post("key/verify", data=input.json(exclude_none=True))
        response.result = VerifyResult(**response.raw_result)
        return response

    # List endpoint
    def list(
        self,
        filter: Optional[Dict[str, List[str]]] = None,
        restrictions: Optional[Dict[str, List[str]]] = None,
        last: Optional[str] = None,
        order: Optional[str] = None,
        order_by: Optional[str] = None,
        size: Optional[int] = None,
    ) -> PangeaResponse[ListResult]:
        input = ListRequest(
            filter=filter, restrictions=restrictions, last=last, order=order, order_by=order_by, size=size
        )
        response = self.request.post("list", data=input.json(exclude_none=True))
        response.result = ListResult(**response.raw_result)
        return response

# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from typing import Dict, List, Optional
import datetime
from base64 import b64encode

from pangea.response import PangeaResponse
from pangea.services.base import ServiceBase
from pangea.services.vault.models.common import (
    ItemType,
    KeyAlgorithm,
    KeyPairPurpose,
    KeyPairAlgorithm,
    Metadata,
    Tags,
    RetrieveCommonRequest,
    RetrieveGenericResult,
    RevokeRequest,
    RevokeResult,
    DeleteRequest,
    DeleteResult,
    ListRequest,
    ListResult,
    UpdateRequest,
    UpdateResult,
)
from pangea.services.vault.models.asymmetric import (
    CreateKeyPairRequest,
    CreateKeyPairResult,
    StoreKeyPairRequest,
    StoreKeyPairResult,
    SignRequest,
    SignResult,
    VerifyRequest,
    VerifyResult,
    RotateKeyPairRequest,
    RotateKeyPairResult,
)
from pangea.services.vault.models.secret import (
    StoreSecretRequest,
    StoreSecretResult,
    RotateSecretRequest,
    RotateSecretResult,
)
from pangea.services.vault.models.symmetric import (
    CreateKeyRequest,
    CreateKeyResult,
    StoreKeyRequest,
    StoreKeyResult,
    RotateKeyRequest,
    RotateKeyResult,
    EncryptRequest,
    EncryptResult,
    DecryptRequest,
    DecryptResult
)


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

    def create_symmetric(
        self,
        algorithm: Optional[KeyAlgorithm] = None,
        name: Optional[str] = None,
        folder: Optional[str] = None,
        metadata: Optional[Metadata] = None,
        tags: Optional[Tags] = None,
        auto_rotate: Optional[bool] = None,
        rotation_policy: Optional[str] = None,
        retain_previous_version: Optional[bool] = None,
        store: Optional[bool] = None,
        expiration: Optional[datetime.datetime] = None,
        managed: Optional[bool] = None,
    ) -> PangeaResponse[CreateKeyResult]:
        input = CreateKeyRequest(
            algorithm=algorithm,
            managed=managed,
            store=store,
            name=name,
            type=ItemType.SYMMETRIC_KEY,
            folder=folder,
            metadata=metadata,
            tags=tags,
            auto_rotate=auto_rotate,
            rotation_policy=rotation_policy,
            retain_previous_version=retain_previous_version,
            expiration=expiration,
        )
        response = self.request.post("key/create", data=input.json(exclude_none=True))
        if response.raw_result is not None:
            response.result = CreateKeyResult(**response.raw_result)
        return response

    def create_asymmetric(
        self,
        algorithm: Optional[KeyAlgorithm] = None,
        purpose: Optional[KeyPairPurpose] = None,
        managed: Optional[bool] = None,
        store: Optional[bool] = None,
        name: Optional[str] = None,
        folder: Optional[str] = None,
        metadata: Optional[Metadata] = None,
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
            type=ItemType.ASYMMETRIC_KEY,
            folder=folder,
            metadata=metadata,
            tags=tags,
            auto_rotate=auto_rotate,
            rotation_policy=rotation_policy,
            retain_previous_version=retain_previous_version,
            expiration=expiration,
        )
        response = self.request.post("key/create", data=input.json(exclude_none=True))
        if response.raw_result is not None:
            response.result = CreateKeyPairResult(**response.raw_result)
        return response

    # Store endpoints
    def store_asymmetric(
        self,
        algorithm: KeyPairAlgorithm,
        public_key: str,
        private_key: str,
        purpose: Optional[KeyPairPurpose] = None,
        name: Optional[str] = None,
        folder: Optional[str] = None,
        metadata: Optional[Metadata] = None,
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
        if response.raw_result is not None:
            response.result = StoreKeyPairResult(**response.raw_result)
        return response

    def store_symmetric(
        self,
        algorithm: KeyAlgorithm,
        key: str,
        name: Optional[str] = None,
        folder: Optional[str] = None,
        metadata: Optional[Metadata] = None,
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
        if response.raw_result is not None:
            response.result = StoreKeyResult(**response.raw_result)
        return response

    def store_secret(
        self,
        secret: str,
        name: Optional[str] = None,
        folder: Optional[str] = None,
        metadata: Optional[Metadata] = None,
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
        if response.raw_result is not None:
            response.result = StoreSecretResult(**response.raw_result)
        return response

    # Retrieve endpoint
    def retrieve(
        self,
        id: str,
        version: Optional[int] = None,
        verbose: Optional[bool] = None,
    ) -> PangeaResponse[RetrieveGenericResult]:
        input = RetrieveCommonRequest(
            id=id,
            version=version,
            verbose=verbose,
        )
        response = self.request.post("get", data=input.json(exclude_none=True))
        if response.raw_result is not None:
            response.result = RetrieveGenericResult(**response.raw_result)
        return response

    # Revoke endpoint
    def revoke(self, id: str) -> PangeaResponse[RevokeResult]:
        input = RevokeRequest(
            id=id,
        )
        response = self.request.post("revoke", data=input.json(exclude_none=True))
        if response.raw_result is not None:
            response.result = RevokeResult(**response.raw_result)
        return response

    # Delete endpoint
    def delete(self, id: str) -> PangeaResponse[DeleteResult]:
        input = DeleteRequest(
            id=id,
        )
        response = self.request.post("delete", data=input.json(exclude_none=True))
        if response.raw_result is not None:
            response.result = DeleteResult(**response.raw_result)
        return response

    # Rotate endpoints
    def rotate_secret(self, id: str, secret: str) -> PangeaResponse[RotateSecretResult]:
        input = RotateSecretRequest(id=id, secret=secret)
        response = self.request.post("secret/rotate", data=input.json(exclude_none=True))
        if response.raw_result is not None:
            response.result = RotateSecretResult(**response.raw_result)
        return response

    def rotate_asymmetric(self, id: str, public_key: Optional[str] = None, private_key: Optional[str] = None) -> PangeaResponse[RotateKeyPairResult]:
        input = RotateKeyPairRequest(id=id, public_key=public_key, private_key=private_key)
        response = self.request.post("key/rotate", data=input.json(exclude_none=True))
        if response.raw_result is not None:
            response.result = RotateKeyPairResult(**response.raw_result)
        return response

    def rotate_symmetric(self, id: str, key: Optional[str] = None) -> PangeaResponse[RotateKeyResult]:
        input = RotateKeyRequest(id=id, key=key)
        response = self.request.post("key/rotate", data=input.json(exclude_none=True))
        if response.raw_result is not None:
            response.result = RotateKeyResult(**response.raw_result)
        return response

    # Encrypt/Decrypt
    def encrypt(self, id: str, plain_text: str) -> PangeaResponse[EncryptResult]:
        input = EncryptRequest(id=id, plain_text=plain_text)
        response = self.request.post("key/encrypt", data=input.json(exclude_none=True))
        if response.raw_result is not None:
            response.result = EncryptResult(**response.raw_result)
        return response

    def decrypt(
        self, id: str, cipher_text: str, version: Optional[int] = None, allow_revoked: Optional[bool] = None
    ) -> PangeaResponse[DecryptResult]:
        input = DecryptRequest(id=id, cipher_text=cipher_text, version=version, allow_revoked=allow_revoked)
        response = self.request.post("key/decrypt", data=input.json(exclude_none=True))
        if response.raw_result is not None:
            response.result = DecryptResult(**response.raw_result)
        return response

    # Sign/Verify endpoints
    def sign(self, id: str, message: str) -> PangeaResponse[SignResult]:
        input = SignRequest(id=id, message=message)
        response = self.request.post("key/sign", data=input.json(exclude_none=True))
        if response.raw_result is not None:
            response.result = SignResult(**response.raw_result)
        return response

    def verify(
        self, id: str, message: str, signature: str, version: Optional[int] = None
    ) -> PangeaResponse[VerifyResult]:
        input = VerifyRequest(
            id=id,
            message=message,
            signature=signature,
            version=version,
        )
        response = self.request.post("key/verify", data=input.json(exclude_none=True))
        if response.raw_result is not None:
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
        if response.raw_result is not None:
            response.result = ListResult(**response.raw_result)
        return response

    # Update endpoint
    def update(
        self,
        id: str,
        name: Optional[str] = None,
        folder: Optional[str] = None,
        metadata: Optional[Metadata] = None,
        tags: Optional[Tags] = None,
        auto_rotate: Optional[bool] = None,
        rotation_policy: Optional[str] = None,
        expiration: Optional[datetime.datetime] = None,
    ) -> PangeaResponse[UpdateResult]:
        input = UpdateRequest(
            id=id,
            name=name,
            folder=folder,
            metadata=metadata,
            tags=tags,
            auto_rotate=auto_rotate,
            rotation_policy=rotation_policy,
            expiration=expiration,
        )
        response = self.request.post("update", data=input.json(exclude_none=True))
        if response.raw_result is not None:
            response.result = UpdateResult(**response.raw_result)
        return response

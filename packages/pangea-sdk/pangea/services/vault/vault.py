# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import datetime
from typing import Dict, Optional

from pangea.response import PangeaResponse
from pangea.services.base import ServiceBase
from pangea.services.vault.models.asymmetric import (
    AsymmetricGenerateRequest,
    AsymmetricGenerateResult,
    AsymmetricStoreRequest,
    AsymmetricStoreResult,
    SignRequest,
    SignResult,
    VerifyRequest,
    VerifyResult,
)
from pangea.services.vault.models.common import (
    AsymmetricAlgorithm,
    DeleteRequest,
    DeleteResult,
    EncodedPrivateKey,
    EncodedPublicKey,
    EncodedSymmetricKey,
    GetRequest,
    GetResult,
    ItemOrder,
    ItemOrderBy,
    ItemType,
    ItemVersionState,
    JWKGetRequest,
    JWKGetResult,
    JWTSignRequest,
    JWTSignResult,
    JWTVerifyRequest,
    JWTVerifyResult,
    KeyPurpose,
    KeyRotateRequest,
    KeyRotateResult,
    ListRequest,
    ListResult,
    Metadata,
    StateChangeRequest,
    StateChangeResult,
    SymmetricAlgorithm,
    Tags,
    UpdateRequest,
    UpdateResult,
)
from pangea.services.vault.models.secret import (
    SecretRotateRequest,
    SecretRotateResult,
    SecretStoreRequest,
    SecretStoreResult,
)
from pangea.services.vault.models.symmetric import (
    DecryptRequest,
    DecryptResult,
    EncryptRequest,
    EncryptResult,
    SymmetricGenerateRequest,
    SymmetricGenerateResult,
    SymmetricStoreRequest,
    SymmetricStoreResult,
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
        logger_name="pangea",
    ):
        super().__init__(token, config, logger_name)

    # Delete endpoint
    def delete(self, id: str) -> PangeaResponse[DeleteResult]:
        input = DeleteRequest(
            id=id,
        )
        response = self.request.post("delete", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = DeleteResult(**response.raw_result)
        return response

    # Get endpoint
    def get(
        self,
        id: str,
        version: Optional[int] = None,
        version_state: Optional[ItemVersionState] = None,
        verbose: Optional[bool] = None,
    ) -> PangeaResponse[GetResult]:
        input = GetRequest(
            id=id,
            version=version,
            verbose=verbose,
            version_state=version_state,
        )
        response = self.request.post("get", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = GetResult(**response.raw_result)
        return response

    # List endpoint
    def list(
        self,
        filter: Optional[Dict[str, str]] = None,
        last: Optional[str] = None,
        order: Optional[ItemOrder] = None,
        order_by: Optional[ItemOrderBy] = None,
        size: Optional[int] = None,
    ) -> PangeaResponse[ListResult]:
        input = ListRequest(filter=filter, last=last, order=order, order_by=order_by, size=size)
        response = self.request.post("list", data=input.dict(exclude_none=True))

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
        rotation_frequency: Optional[str] = None,
        rotation_state: Optional[ItemVersionState] = None,
        expiration: Optional[datetime.datetime] = None,
        state: Optional[str] = None,  # FIXME: This should be VersionState, shouldn't it?
    ) -> PangeaResponse[UpdateResult]:
        input = UpdateRequest(
            id=id,
            name=name,
            folder=folder,
            metadata=metadata,
            tags=tags,
            rotation_frequency=rotation_frequency,
            rotation_state=rotation_state,
            expiration=expiration,
            state=state,
        )
        response = self.request.post("update", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = UpdateResult(**response.raw_result)
        return response

    def secret_store(
        self,
        secret: str,
        name: Optional[str] = None,
        folder: Optional[str] = None,
        metadata: Optional[Metadata] = None,
        tags: Optional[Tags] = None,
        rotation_frequency: Optional[str] = None,
        rotation_state: Optional[ItemVersionState] = None,
        expiration: Optional[datetime.datetime] = None,
    ) -> PangeaResponse[SecretStoreResult]:
        input = SecretStoreRequest(
            type=ItemType.SECRET,
            secret=secret,
            name=name,
            folder=folder,
            metadata=metadata,
            tags=tags,
            rotation_frequency=rotation_frequency,
            rotation_state=rotation_state,
            expiration=expiration,
        )
        response = self.request.post("secret/store", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = SecretStoreResult(**response.raw_result)
        return response

    def pangea_token_store(
        self,
        pangea_token: str,
        name: Optional[str] = None,
        folder: Optional[str] = None,
        metadata: Optional[Metadata] = None,
        tags: Optional[Tags] = None,
        rotation_frequency: Optional[str] = None,
        rotation_state: Optional[ItemVersionState] = None,
        expiration: Optional[datetime.datetime] = None,
    ) -> PangeaResponse[SecretStoreResult]:
        input = SecretStoreRequest(
            type=ItemType.PANGEA_TOKEN,
            secret=pangea_token,
            name=name,
            folder=folder,
            metadata=metadata,
            tags=tags,
            rotation_frequency=rotation_frequency,
            rotation_state=rotation_state,
            expiration=expiration,
        )
        response = self.request.post("secret/store", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = SecretStoreResult(**response.raw_result)
        return response

    # Rotate endpoint
    def secret_rotate(
        self, id: str, secret: str, rotation_state: Optional[ItemVersionState] = None
    ) -> PangeaResponse[SecretRotateResult]:
        input = SecretRotateRequest(id=id, secret=secret, rotation_state=rotation_state)
        response = self.request.post("secret/rotate", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = SecretRotateResult(**response.raw_result)
        return response

    # Rotate endpoint
    def pangea_token_rotate(self, id: str) -> PangeaResponse[SecretRotateResult]:
        input = SecretRotateRequest(id=id)
        response = self.request.post("secret/rotate", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = SecretRotateResult(**response.raw_result)
        return response

    def symmetric_generate(
        self,
        algorithm: Optional[SymmetricAlgorithm] = None,
        purpose: Optional[KeyPurpose] = None,
        name: Optional[str] = None,
        folder: Optional[str] = None,
        metadata: Optional[Metadata] = None,
        tags: Optional[Tags] = None,
        rotation_frequency: Optional[str] = None,
        rotation_state: Optional[ItemVersionState] = None,
        expiration: Optional[datetime.datetime] = None,
    ) -> PangeaResponse[SymmetricGenerateResult]:
        input = SymmetricGenerateRequest(
            type=ItemType.SYMMETRIC_KEY,
            algorithm=algorithm,
            purpose=purpose,
            name=name,
            folder=folder,
            metadata=metadata,
            tags=tags,
            rotation_frequency=rotation_frequency,
            rotation_state=rotation_state,
            expiration=expiration,
        )
        response = self.request.post("key/generate", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = SymmetricGenerateResult(**response.raw_result)
        return response

    def asymmetric_generate(
        self,
        algorithm: Optional[SymmetricAlgorithm] = None,
        purpose: Optional[KeyPurpose] = None,
        name: Optional[str] = None,
        folder: Optional[str] = None,
        metadata: Optional[Metadata] = None,
        tags: Optional[Tags] = None,
        rotation_frequency: Optional[str] = None,
        rotation_state: Optional[ItemVersionState] = None,
        expiration: Optional[datetime.datetime] = None,
    ) -> PangeaResponse[AsymmetricGenerateResult]:
        input = AsymmetricGenerateRequest(
            type=ItemType.ASYMMETRIC_KEY,
            algorithm=algorithm,
            purpose=purpose,
            name=name,
            folder=folder,
            metadata=metadata,
            tags=tags,
            rotation_frequency=rotation_frequency,
            rotation_state=rotation_state,
            expiration=expiration,
        )
        response = self.request.post("key/generate", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = AsymmetricGenerateResult(**response.raw_result)
        return response

    # Store endpoints
    def asymmetric_store(
        self,
        algorithm: AsymmetricAlgorithm,
        public_key: EncodedPublicKey,
        private_key: EncodedPrivateKey,
        purpose: Optional[KeyPurpose] = None,
        name: Optional[str] = None,
        folder: Optional[str] = None,
        metadata: Optional[Metadata] = None,
        tags: Optional[Tags] = None,
        rotation_frequency: Optional[str] = None,
        rotation_state: Optional[ItemVersionState] = None,
        expiration: Optional[datetime.datetime] = None,
    ) -> PangeaResponse[AsymmetricStoreResult]:
        input = AsymmetricStoreRequest(
            type=ItemType.ASYMMETRIC_KEY,
            algorithm=algorithm,
            purpose=purpose,
            public_key=public_key,
            private_key=private_key,
            name=name,
            folder=folder,
            metadata=metadata,
            tags=tags,
            rotation_frequency=rotation_frequency,
            rotation_state=rotation_state,
            expiration=expiration,
        )
        response = self.request.post("key/store", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = AsymmetricStoreResult(**response.raw_result)
        return response

    def symmetric_store(
        self,
        algorithm: SymmetricAlgorithm,
        key: str,
        purpose: Optional[KeyPurpose] = None,
        name: Optional[str] = None,
        folder: Optional[str] = None,
        metadata: Optional[Metadata] = None,
        tags: Optional[Tags] = None,
        rotation_frequency: Optional[str] = None,
        rotation_state: Optional[ItemVersionState] = None,
        expiration: Optional[datetime.datetime] = None,
    ) -> PangeaResponse[SymmetricStoreResult]:
        input = SymmetricStoreRequest(
            type=ItemType.SYMMETRIC_KEY,
            algorithm=algorithm,
            purpose=purpose,
            key=key,
            name=name,
            folder=folder,
            metadata=metadata,
            tags=tags,
            rotation_frequency=rotation_frequency,
            rotation_state=rotation_state,
            expiration=expiration,
        )
        response = self.request.post("key/store", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = SymmetricStoreResult(**response.raw_result)
        return response

    # Rotate endpoint
    def key_rotate(
        self,
        id: str,
        rotation_state: ItemVersionState,
        public_key: Optional[EncodedPublicKey] = None,
        private_key: Optional[EncodedPrivateKey] = None,
        key: Optional[EncodedSymmetricKey] = None,
    ) -> PangeaResponse[KeyRotateResult]:
        input = KeyRotateRequest(
            id=id, public_key=public_key, private_key=private_key, key=key, rotation_state=rotation_state
        )
        response = self.request.post("key/rotate", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = KeyRotateResult(**response.raw_result)
        return response

    # Encrypt/Decrypt
    def encrypt(self, id: str, plain_text: str, version: Optional[int] = None) -> PangeaResponse[EncryptResult]:
        input = EncryptRequest(id=id, plain_text=plain_text, version=version)
        response = self.request.post("key/encrypt", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = EncryptResult(**response.raw_result)
        return response

    def decrypt(self, id: str, cipher_text: str, version: Optional[int] = None) -> PangeaResponse[DecryptResult]:
        input = DecryptRequest(id=id, cipher_text=cipher_text, version=version)
        response = self.request.post("key/decrypt", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = DecryptResult(**response.raw_result)
        return response

    # Sign/Verify endpoints
    def sign(self, id: str, message: str, version: Optional[int] = None) -> PangeaResponse[SignResult]:
        input = SignRequest(id=id, message=message, version=version)
        response = self.request.post("key/sign", data=input.dict(exclude_none=True))
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
        response = self.request.post("key/verify", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = VerifyResult(**response.raw_result)
        return response

    def jwt_verify(self, jws: str) -> PangeaResponse[JWTVerifyResult]:
        input = JWTVerifyRequest(jws=jws)
        response = self.request.post("key/verify/jwt", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = JWTVerifyResult(**response.raw_result)
        return response

    def jwt_sign(self, id: str, payload: str) -> PangeaResponse[JWTSignResult]:
        input = JWTSignRequest(id=id, payload=payload)
        response = self.request.post("key/sign/jwt", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = JWTSignResult(**response.raw_result)
        return response

    # Get endpoint
    def jwk_get(self, id: str, version: Optional[str] = None) -> PangeaResponse[JWKGetResult]:
        input = JWKGetRequest(id=id, version=version)
        response = self.request.post("get/jwk", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = JWKGetResult(**response.raw_result)
        return response

    # State change
    def state_change(self, id: str, state: ItemVersionState, version: int) -> PangeaResponse[StateChangeResult]:
        input = StateChangeRequest(id=id, state=state, version=version)
        response = self.request.post("state/change", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = StateChangeResult(**response.raw_result)
        return response

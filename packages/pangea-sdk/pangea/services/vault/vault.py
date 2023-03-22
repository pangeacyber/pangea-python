# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import datetime
from typing import Dict, Optional, Union

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
    ItemState,
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
        """
        Delete

        Delete a secret or key
        
        Args:
            id (str): The item ID
        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the id of the deleted secret or key
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#delete).

        Examples:
            vault.delete(id="pvi_p6g5i3gtbvqvc3u6zugab6qs6r63tqf5")
        """
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
        version: Optional[Union[str, int]] = None,
        version_state: Optional[ItemVersionState] = None,
        verbose: Optional[bool] = None,
    ) -> PangeaResponse[GetResult]:
        """
        Retrieve

        Retrieve a secret or key, and any associated information
        
        Args:
            id (str): The item ID
            version (str, int, optional): The key version(s). 
                - `all` for all versions
                - `num` for a specific version
                - `-num` for the `num` latest versions
            version_state (ItemVersionState, optional): The state of the item version
            verbose (bool, optional): Return metadata and extra fields. Default is `False`.
        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the secret or key
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#retrieve).

        Examples:
            vault.get(
                id="pvi_p6g5i3gtbvqvc3u6zugab6qs6r63tqf5",
                version=1,
                version_state=ItemVersionState.ACTIVE,
                verbose=True,
            )
        """
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
        """
        List

        Look up a list of secrets, keys and folders, and their associated information
        
        Args:
            filter (dict, optional): A set of filters to help you customize your search. Examples:
                - "folder": "/tmp"
                - "tags": "personal"
                - "name__contains": "xxx"
                - "created_at__gt": "2020-02-05T10:00:00Z"

                For metadata, use: "metadata_": "\<value\>"
            last (str, optional): Internal ID returned in the previous look up response. Used for pagination.
            order (ItemOrder, optional): Ordering direction: `asc` or `desc`
            order_by (ItemOrderBy, optional): Property used to order the results. Supported properties: `id`,
                `type`, `created_at`, `algorithm`, `purpose`, `expiration`, `last_rotated`, `next_rotation`,
                `name`, `folder`, `item_state`.
            size (int, optional): Maximum number of items in the response. Default is `50`.
        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where a list of secrets or keys
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#list).

        Examples:
            vault.list(
                filter={
                    "folder": "/",
                    "type": "asymmetric_key",
                    "name__contains": "test",
                    "metadata_key1": "value1",
                    "created_at__lt": "2023-12-12T00:00:00Z"
                },
                last="WyIvdGVzdF8yMDdfc3ltbWV0cmljLyJd",
                order=ItemOrder.ASC,
                order_by=ItemOrderBy.NAME,
                size=20,
            )
        """
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
        rotation_grace_period: Optional[str] = None,
        expiration: Optional[datetime.datetime] = None,
        item_state: Optional[ItemState] = None,
    ) -> PangeaResponse[UpdateResult]:
        """
        Update

        Update information associated with a secret or key.
        
        Args:
            id (str): The item ID
            name (str, optional): The name of this item
            folder (string, optional): The folder where this item is stored
            metadata (dict, optional): User-provided metadata
            tags (list[str], optional): A list of user-defined tags
            rotation_frequency (str, optional): Period of time between item rotations
            rotation_state (ItemVersionState, optional): State to which the previous version should transition upon rotation.
                Supported options:
                - `deactivated`
                - `destroyed`

                Default is `deactivated`.
            rotation_grace_period (str, optional): Grace period for the previous version of the Pangea Token
            expiration (str, optional): Expiration timestamp
            item_state (ItemState, optional): The new state of the item. Supported options:
                - `enabled`
                - `disabled`
        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the item ID
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#update).

        Examples:
            vault.update(
                id="pvi_p6g5i3gtbvqvc3u6zugab6qs6r63tqf5",
                name="my-very-secret-secret",
                folder="/personal",
                metadata={
                    "created_by": "John Doe",
                    "used_in": "Google products"
                },
                tags=[
                    "irs_2023",
                    "personal"
                ],
                rotation_frequency="10d",
                rotation_state=ItemVersionState.DEACTIVATED,
                rotation_grace_period="1d",
                expiration="2025-01-01T10:00:00Z",
                item_state=ItemState.DISABLED,
            )
        """
        input = UpdateRequest(
            id=id,
            name=name,
            folder=folder,
            metadata=metadata,
            tags=tags,
            rotation_frequency=rotation_frequency,
            rotation_state=rotation_state,
            rotation_grace_period=rotation_grace_period,
            expiration=expiration,
            item_state=item_state,
        )
        response = self.request.post("update", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = UpdateResult(**response.raw_result)
        return response

    def secret_store(
        self,
        secret: str,
        name: str,
        folder: Optional[str] = None,
        metadata: Optional[Metadata] = None,
        tags: Optional[Tags] = None,
        rotation_frequency: Optional[str] = None,
        rotation_state: Optional[ItemVersionState] = None,
        expiration: Optional[datetime.datetime] = None,
    ) -> PangeaResponse[SecretStoreResult]:
        """
        Secret store

        Import a secret
        
        Args:
            secret (str): The secret value
            name (str): The name of this item
            folder (str, optional): The folder where this item is stored
            metadata (dict, optional): User-provided metadata
            tags (list[str], optional): A list of user-defined tags
            rotation_frequency (str, optional): Period of time between item rotations
            rotation_state (ItemVersionState, optional): State to which the previous version should transition upon rotation.
                Supported options:
                - `deactivated`
                - `destroyed`
            expiration (str, optional): Expiration timestamp

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the secret
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#import-a-secret).

        Examples:
            vault.secret_store(
                secret="12sdfgs4543qv@#%$casd",
                name="my-very-secret-secret",
                folder="/personal",
                metadata={
                    "created_by": "John Doe",
                    "used_in": "Google products"
                },
                tags=[
                    "irs_2023",
                    "personal"
                ],
                rotation_frequency="10d",
                rotation_state=ItemVersionState.DEACTIVATED,
                expiration="2025-01-01T10:00:00Z",
            )
        """
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
        name: str,
        folder: Optional[str] = None,
        metadata: Optional[Metadata] = None,
        tags: Optional[Tags] = None,
        rotation_frequency: Optional[str] = None,
        rotation_state: Optional[ItemVersionState] = None,
        expiration: Optional[datetime.datetime] = None,
    ) -> PangeaResponse[SecretStoreResult]:
        """
        Pangea token store

        Import a secret
        
        Args:
            pangea_token (str): The pangea token to store
            name (str): the name of this item
            folder (str, optional): The folder where this item is stored
            metadata (dict, optional): User-provided metadata
            tags (list[str], optional): A list of user-defined tags
            rotation_frequency (str, optional): Period of time between item rotations
            rotation_state (ItemVersionState, optional): State to which the previous version should 
                transition upon rotation. Supported options:
                - `deactivated`
                - `destroyed`
            expiration (str, optional): Expiration timestamp

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the token
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#import-a-secret).

        Examples:
            vault.pangea_token_store(
                pangea_token="ptv_x6fdiizbon6j3bsdvnpmwxsz2aan7fqd",
                name="my-very-secret-secret",
                folder="/personal",
                metadata={
                    "created_by": "John Doe",
                    "used_in": "Google products"
                },
                tags=[
                    "irs_2023",
                    "personal"
                ],
                rotation_frequency="10d",
                rotation_state=ItemVersionState.DEACTIVATED,
                expiration="2025-01-01T10:00:00Z",
            )
        """
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
        """
        Secret rotate

        Rotate a secret
        
        Args:
            id (str): The item ID
            secret (str): The secret value
            rotation_state (ItemVersionState, optional): State to which the previous version should transition upon rotation.
                Supported options:
                - `deactivated`
                - `suspended`
                - `destroyed`

                Default is `deactivated`.

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the secret
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#rotate-a-secret).

        Examples:
            vault.secret_rotate(
                id="pvi_p6g5i3gtbvqvc3u6zugab6qs6r63tqf5",
                secret="12sdfgs4543qv@#%$casd",
                rotation_state=ItemVersionState.DEACTIVATED,
            )
        """
        input = SecretRotateRequest(id=id, secret=secret, rotation_state=rotation_state)
        response = self.request.post("secret/rotate", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = SecretRotateResult(**response.raw_result)
        return response

    # Rotate endpoint
    def pangea_token_rotate(self, id: str) -> PangeaResponse[SecretRotateResult]:
        """
        Token rotate

        Rotate a Pangea token
        
        Args:
            id (str): The item ID

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the token
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#rotate-a-secret).

        Examples:
            vault.pangea_token_rotate(
                id="pvi_p6g5i3gtbvqvc3u6zugab6qs6r63tqf5",
            )
        """
        input = SecretRotateRequest(id=id)
        response = self.request.post("secret/rotate", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = SecretRotateResult(**response.raw_result)
        return response

    def symmetric_generate(
        self,
        algorithm: SymmetricAlgorithm,
        purpose: KeyPurpose,
        name: Optional[str] = None,
        folder: Optional[str] = None,
        metadata: Optional[Metadata] = None,
        tags: Optional[Tags] = None,
        rotation_frequency: Optional[str] = None,
        rotation_state: Optional[ItemVersionState] = None,
        expiration: Optional[datetime.datetime] = None,
    ) -> PangeaResponse[SymmetricGenerateResult]:
        """
        Symmetric generate

        Generate a symmetric key
        
        Args:
            algorithm (SymmetricAlgorithm): The algorithm of the key
            purpose (KeyPurpose): The purpose of this key
            name (str): The name of this item
            folder (str, optional): The folder where this item is stored
            metadata (dict, optional): User-provided metadata
            tags (list[str], optional): A list of user-defined tags
            rotation_frequency (str, optional): Period of time between item rotations, or `never` to disallow rotation
            rotation_state (ItemVersionState, optional): State to which the previous version should transition upon rotation.
                Supported options:
                - `deactivated`
                - `destroyed`
            expiration (str, optional): Expiration timestamp

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the ID of the key
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#generate).

        Examples:
            vault.symmetric_generate(
                algorithm=SymmetricAlgorithm.AES,
                purpose=KeyPurpose.ENCRYPTION,
                name="my-very-secret-secret",
                folder="/personal",
                metadata={
                    "created_by": "John Doe",
                    "used_in": "Google products"
                },
                tags=[
                    "irs_2023",
                    "personal"
                ],
                rotation_frequency="10d",
                rotation_state=ItemVersionState.DEACTIVATED,
                expiration="2025-01-01T10:00:00Z",
            )
        """
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
        algorithm: AsymmetricAlgorithm,
        purpose: KeyPurpose,
        name: Optional[str] = None,
        folder: Optional[str] = None,
        metadata: Optional[Metadata] = None,
        tags: Optional[Tags] = None,
        rotation_frequency: Optional[str] = None,
        rotation_state: Optional[ItemVersionState] = None,
        expiration: Optional[datetime.datetime] = None,
    ) -> PangeaResponse[AsymmetricGenerateResult]:
        """
        Asymmetric generate

        Generate an asymmetric key
        
        Args:
            algorithm (AsymmetricAlgorithm): The algorithm of the key
            purpose (KeyPurpose): The purpose of this key
            name (str): The name of this item
            folder (str, optional): The folder where this item is stored
            metadata (dict, optional): User-provided metadata
            tags (list[str], optional): A list of user-defined tags
            rotation_frequency (str, optional): Period of time between item rotations, or `never` to disallow rotation
            rotation_state (ItemVersionState, optional): State to which the previous version should transition upon rotation.
                Supported options:
                - `deactivated`
                - `destroyed`
            expiration (str, optional): Expiration timestamp

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the ID of the key
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#generate).

        Examples:
            vault.asymmetric_generate(
                algorithm=AsymmetricAlgorithm.RSA,
                purpose=KeyPurpose.SIGNING,
                name="my-very-secret-secret",
                folder="/personal",
                metadata={
                    "created_by": "John Doe",
                    "used_in": "Google products"
                },
                tags=[
                    "irs_2023",
                    "personal"
                ],
                rotation_frequency="10d",
                rotation_state=ItemVersionState.DEACTIVATED,
                expiration="2025-01-01T10:00:00Z",
            )
        """
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
        private_key: EncodedPrivateKey,
        public_key: EncodedPublicKey,
        algorithm: AsymmetricAlgorithm,
        purpose: KeyPurpose,
        name: str,
        folder: Optional[str] = None,
        metadata: Optional[Metadata] = None,
        tags: Optional[Tags] = None,
        rotation_frequency: Optional[str] = None,
        rotation_state: Optional[ItemVersionState] = None,
        expiration: Optional[datetime.datetime] = None,
    ) -> PangeaResponse[AsymmetricStoreResult]:
        """
        Asymmetric store

        Import an asymmetric key
        
        Args:
            private_key (EncodedPrivateKey): The private key in PEM format
            public_key (EncodedPublicKey): The public key in PEM format
            algorithm (AsymmetricAlgorithm): The algorithm of the key
            purpose (KeyPurpose): The purpose of this key. `signing`, `encryption`, or `jwt`.
            name (str): The name of this item
            folder (str, optional): The folder where this item is stored
            metadata (dict, optional): User-provided metadata
            tags (list[str], optional): A list of user-defined tags
            rotation_frequency (str, optional): Period of time between item rotations, or `never` to disallow rotation
            rotation_state (ItemVersionState, optional): State to which the previous version should transition upon rotation.
                Supported options:
                - `deactivated`
                - `destroyed`
            expiration (str, optional): Expiration timestamp

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the ID and public key
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#import-a-key).

        Examples:
            vault.asymmetric_store(
                private_key="private key example",
                public_key="-----BEGIN PUBLIC KEY-----\\nMCowBQYDK2VwAyEA8s5JopbEPGBylPBcMK+L5PqHMqPJW/5KYPgBHzZGncc=\\n-----END PUBLIC KEY-----",
                algorithm="AsymmetricAlgorithm.RSA,
                purpose=KeyPurpose.SIGNING,
                name="my-very-secret-secret",
                folder="/personal",
                metadata={
                    "created_by": "John Doe",
                    "used_in": "Google products"
                },
                tags=[
                    "irs_2023",
                    "personal"
                ],
                rotation_frequency="10d",
                rotation_state=ItemVersionState.DEACTIVATED,
                expiration="2025-01-01T10:00:00Z",
            )
        """
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
        key: str,
        algorithm: SymmetricAlgorithm,
        purpose: KeyPurpose,
        name: str,
        folder: Optional[str] = None,
        metadata: Optional[Metadata] = None,
        tags: Optional[Tags] = None,
        rotation_frequency: Optional[str] = None,
        rotation_state: Optional[ItemVersionState] = None,
        expiration: Optional[datetime.datetime] = None,
    ) -> PangeaResponse[SymmetricStoreResult]:
        """
        Symmetric store

        Import a symmetric key
        
        Args:
            key (str): The key material (in base64)
            algorithm (SymmetricAlgorithm): The algorithm of the key
            purpose (KeyPurpose): The purpose of this key. `encryption` or `jwt`
            name (str): The name of this item
            folder (str, optional): The folder where this item is stored
            metadata (dict, optional): User-provided metadata
            tags (list[str], optional): A list of user-defined tags
            rotation_frequency (str, optional): Period of time between item rotations, or `never` to disallow rotation
            rotation_state (ItemVersionState, optional): State to which the previous version should transition upon rotation.
                Supported options:
                - `deactivated`
                - `destroyed`
            expiration (str, optional): Expiration timestamp

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the ID
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#import-a-key).

        Examples:
            vault.symmetric_store(
                key="lJkk0gCLux+Q+rPNqLPEYw==",
                algorithm=SymmetricAlgorithm.AES,
                purpose=KeyPurpose.ENCRYPTION,
                name="my-very-secret-secret",
                folder="/personal",
                metadata={
                    "created_by": "John Doe",
                    "used_in": "Google products"
                },
                tags=[
                    "irs_2023",
                    "personal"
                ],
                rotation_frequency="10d",
                rotation_state=ItemVersionState.DEACTIVATED,
                expiration="2025-01-01T10:00:00Z",
            )
        """
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
        """
        Key rotate

        Manually rotate a symmetric or asymmetric key
        
        Args:
            id (str): The ID of the item
            rotation_state (ItemVersionState, optional): State to which the previous version should transition upon rotation.
                Supported options:
                - `deactivated`
                - `suspended`
                - `destroyed`

                Default is `deactivated`.
            public_key (EncodedPublicKey, optional): The public key (in PEM format)
            private_key: (EncodedPrivateKey, optional): The private key (in PEM format)
            key: (EncodedSymmetricKey, optional): The key material (in base64)

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the ID
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#rotate).

        Examples:
            vault.key_rotate(
                id="pvi_p6g5i3gtbvqvc3u6zugab6qs6r63tqf5",
                rotation_state=ItemVersionState.DEACTIVATED,
                key="lJkk0gCLux+Q+rPNqLPEYw==",
            )
        """
        input = KeyRotateRequest(
            id=id, public_key=public_key, private_key=private_key, key=key, rotation_state=rotation_state
        )
        response = self.request.post("key/rotate", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = KeyRotateResult(**response.raw_result)
        return response

    # Encrypt
    def encrypt(self, id: str, plain_text: str, version: Optional[int] = None) -> PangeaResponse[EncryptResult]:
        """
        Encrypt

        Encrypt a message using a key
        
        Args:
            id (str): The item ID
            plain_text (str): A message to be in encrypted (in base64)
            version (int, optional): The item version

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the encrypted message in base64
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#encrypt).

        Examples:
            vault.encrypt(
                id="pvi_p6g5i3gtbvqvc3u6zugab6qs6r63tqf5",
                plain_text="lJkk0gCLux+Q+rPNqLPEYw==",
                version=1,
            )
        """
        input = EncryptRequest(id=id, plain_text=plain_text, version=version)
        response = self.request.post("key/encrypt", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = EncryptResult(**response.raw_result)
        return response

    # Decrypt
    def decrypt(self, id: str, cipher_text: str, version: Optional[int] = None) -> PangeaResponse[DecryptResult]:
        """
        Decrypt

        Decrypt a message using a key
        
        Args:
            id (str): The item ID
            cipher_text (str): A message encrypted by Vault (in base64)
            version (int, optional): The item version

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the decrypted message in base64
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#decrypt).

        Examples:
            vault.decrypt(
                id="pvi_p6g5i3gtbvqvc3u6zugab6qs6r63tqf5",
                cipher_text="lJkk0gCLux+Q+rPNqLPEYw==",
                version=1,
            )
        """
        input = DecryptRequest(id=id, cipher_text=cipher_text, version=version)
        response = self.request.post("key/decrypt", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = DecryptResult(**response.raw_result)
        return response

    # Sign
    def sign(self, id: str, message: str, version: Optional[int] = None) -> PangeaResponse[SignResult]:
        """
        Sign

        Sign a message using a key
        
        Args:
            id (str): The item ID
            message (str): The message to be signed, in base64
            version (int, optional): The item version

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the signature of the message in base64
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#sign).

        Examples:
            vault.sign(
                id="pvi_p6g5i3gtbvqvc3u6zugab6qs6r63tqf5",
                message="lJkk0gCLux+Q+rPNqLPEYw==",
                version=1,
            )
        """
        input = SignRequest(id=id, message=message, version=version)
        response = self.request.post("key/sign", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = SignResult(**response.raw_result)
        return response

    # Verify
    def verify(
        self, id: str, message: str, signature: str, version: Optional[int] = None
    ) -> PangeaResponse[VerifyResult]:
        """
        Verify

        Verify a signature using a key
        
        Args:
            id (str): The item ID
            message (str): A message to be verified (in base64)
            signature (str): The message signature (in base64)
            version (int, optional): The item version

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the signature is valid
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#verify).

        Examples:
            vault.verify(
                id="pvi_p6g5i3gtbvqvc3u6zugab6qs6r63tqf5",
                message="lJkk0gCLux+Q+rPNqLPEYw==",
                signature="FfWuT2Mq/+cxa7wIugfhzi7ktZxVf926idJNgBDCysF/knY9B7M6wxqHMMPDEBs86D8OsEGuED21y3J7IGOpCQ==",
                version=1,
            )
        """
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
        """
        JWT Verify

        Verify the signature of a JSON Web Token (JWT)
        
        Args:
            jws (str): The signed JSON Web Token (JWS)

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the signature is valid
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#verify-jwt).

        Examples:
            vault.jwt_verify(
                jws="ewogICJhbGciO..."
            )
        """
        input = JWTVerifyRequest(jws=jws)
        response = self.request.post("key/verify/jwt", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = JWTVerifyResult(**response.raw_result)
        return response

    def jwt_sign(self, id: str, payload: str) -> PangeaResponse[JWTSignResult]:
        """
        JWT Sign

        Sign a JSON Web Token (JWT) using a key
        
        Args:
            id (str): The item ID
            payload (str): The JWT payload (in JSON)

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the signed JSON Web Token (JWS)
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#sign-a-jwt).

        Examples:
            vault.jwt_sign(
                id="pvi_p6g5i3gtbvqvc3u6zugab6qs6r63tqf5",
                payload="{\\"sub\\": \\"1234567890\\",\\"name\\": \\"John Doe\\",\\"admin\\": true}"
            )
        """
        input = JWTSignRequest(id=id, payload=payload)
        response = self.request.post("key/sign/jwt", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = JWTSignResult(**response.raw_result)
        return response

    # Get endpoint
    def jwk_get(self, id: str, version: Optional[str] = None) -> PangeaResponse[JWKGetResult]:
        """
        JWT Retrieve

        Retrieve a key in JWK format
        
        Args:
            id (str): The item ID
            version (str, optional): The key version(s).
                - `all` for all versions
                - `num` for a specific version
                - `-num` for the `num` latest versions
        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the JSON Web Key Set (JWKS) object
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#retrieve-jwk").

        Examples:
            vault.jwk_get(
                id="pvi_p6g5i3gtbvqvc3u6zugab6qs6r63tqf5",
            )
        """
        input = JWKGetRequest(id=id, version=version)
        response = self.request.post("get/jwk", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = JWKGetResult(**response.raw_result)
        return response

    # State change
    def state_change(
        self, id: str, state: ItemVersionState, version: Optional[int] = None, destroy_period: Optional[str] = None
    ) -> PangeaResponse[StateChangeResult]:
        """
        State change

        Change the state of a specific version of a secret or key
        
        Args:
            id (str): The item ID
            state (ItemVersionState): The new state of the item version. Supported options:
                - `active`
                - `deactivated`
                - `suspended`
                - `compromised`
                - `destroyed`
            version (int, optional): the item version
            destroy_period (str, optional): Period of time for the destruction of a compromised key. 
                Only valid if state=`compromised`
        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the state change object
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#change-state").

        Examples:
            vault.state_change(
                id="pvi_p6g5i3gtbvqvc3u6zugab6qs6r63tqf5",
                state=ItemVersionState.DEACTIVATED,
            )
        """
        input = StateChangeRequest(id=id, state=state, version=version, destroy_period=destroy_period)
        response = self.request.post("state/change", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = StateChangeResult(**response.raw_result)
        return response

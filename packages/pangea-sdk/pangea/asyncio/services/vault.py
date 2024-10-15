# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, List, Literal, Optional, Union, cast, overload

from pydantic import Field, TypeAdapter
from typing_extensions import Annotated

from pangea.asyncio.services.base import ServiceBaseAsync
from pangea.config import PangeaConfig
from pangea.response import PangeaResponse, PangeaResponseResult
from pangea.services.vault.models.asymmetric import (
    AsymmetricKey,
    AsymmetricKeyAlgorithm,
    AsymmetricKeyEncryptionAlgorithm,
    AsymmetricKeyJwtAlgorithm,
    AsymmetricKeyPkiAlgorithm,
    AsymmetricKeyPurpose,
    AsymmetricKeySigningAlgorithm,
    SignRequest,
    SignResult,
    VerifyRequest,
    VerifyResult,
)
from pangea.services.vault.models.common import (
    ClientSecret,
    ClientSecretRotateRequest,
    DecryptTransformRequest,
    DecryptTransformResult,
    DeleteRequest,
    DeleteResult,
    EncryptStructuredRequest,
    EncryptStructuredResult,
    EncryptTransformRequest,
    EncryptTransformResult,
    ExportEncryptionAlgorithm,
    ExportRequest,
    ExportResult,
    Folder,
    FolderCreateRequest,
    FolderCreateResult,
    GetBulkRequest,
    GetRequest,
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
    ListRequest,
    ListResult,
    Metadata,
    PangeaToken,
    PangeaTokenRotateRequest,
    RequestManualRotationState,
    RequestRotationState,
    RotationState,
    Secret,
    StateChangeRequest,
    Tags,
    TDict,
    TransformAlphabet,
    UpdateRequest,
    UpdateResult,
)
from pangea.services.vault.models.keys import CommonGenerateRequest, KeyRotateRequest, KeyStoreRequest
from pangea.services.vault.models.secret import SecretRotateRequest, SecretStoreRequest, SecretStoreResult
from pangea.services.vault.models.symmetric import (
    DecryptRequest,
    DecryptResult,
    EncryptRequest,
    EncryptResult,
    SymmetricKey,
    SymmetricKeyAlgorithm,
    SymmetricKeyEncryptionAlgorithm,
    SymmetricKeyFpeAlgorithm,
    SymmetricKeyJwtAlgorithm,
    SymmetricKeyPurpose,
)

if TYPE_CHECKING:
    import datetime
    from collections.abc import Mapping

    from pangea.config import PangeaConfig
    from pangea.request import TResult

VaultItem = Annotated[
    Union[AsymmetricKey, SymmetricKey, Secret, ClientSecret, Folder, PangeaToken], Field(discriminator="type")
]
vault_item_adapter: TypeAdapter[VaultItem] = TypeAdapter(VaultItem)


class GetBulkResponse(PangeaResponseResult):
    items: List[VaultItem]


class VaultAsync(ServiceBaseAsync):
    """Vault service client.

    Provides methods to interact with the [Pangea Vault Service](https://pangea.cloud/docs/api/vault).

    The following information is needed:
        PANGEA_VAULT_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)

    Examples:
        import os

        # Pangea SDK
        from pangea.asyncio.services import VaultAsync
        from pangea.config import PangeaConfig

        PANGEA_VAULT_TOKEN = os.getenv("PANGEA_VAULT_TOKEN")
        vault_config = PangeaConfig(domain="pangea.cloud")

        # Setup Pangea Vault service
        vault = VaultAsync(token=PANGEA_VAULT_TOKEN, config=vault_config)
    """

    service_name = "vault"

    def __init__(
        self,
        token: str,
        config: PangeaConfig | None = None,
        logger_name: str = "pangea",
    ) -> None:
        """
        Vault client

        Initializes a new Vault client.

        Args:
            token: Pangea API token.
            config: Configuration.
            logger_name: Logger name.

        Examples:
             config = PangeaConfig(domain="pangea_domain")
             vault = VaultAsync(token="pangea_token", config=config)
        """
        super().__init__(token, config, logger_name)

    async def delete(self, item_id: str, *, recursive: bool = False) -> PangeaResponse[DeleteResult]:
        """
        Delete

        Delete a secret or key

        OperationId: vault_post_v2_delete

        Args:
            item_id: The item ID.
            recursive: Whether to delete the item and all its children
              recursively. Only applicable to folders.

        Returns:
            A PangeaResponse where the id of the deleted secret or key
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#delete).

        Raises:
            PangeaAPIException: If an API Error happens

        Examples:
            await vault.delete(id="pvi_p6g5i3gtbvqvc3u6zugab6qs6r63tqf5")
        """
        return await self.request.post("v2/delete", DeleteResult, data=DeleteRequest(id=item_id, recursive=recursive))

    async def get(
        self,
        item_id: str,
        *,
        version: Union[Literal["all"], int, None] = None,
    ) -> PangeaResponse[VaultItem]:
        """
        Retrieve

        Retrieve a secret, key or folder, and any associated information.

        OperationId: vault_post_v2_get

        Args:
            item_id: The item ID
            version: The key version(s).
              - `all` for all versions
              - `num` for a specific version
              - `-num` for the `num` latest versions

        Returns:
            A PangeaResponse where the secret or key
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#retrieve).

        Raises:
            PangeaAPIException: If an API Error happens

        Examples:
            response = await vault.get(
                id="pvi_p6g5i3gtbvqvc3u6zugab6qs6r63tqf5",
                version=1,
            )
        """
        response = await self.request.post("v2/get", PangeaResponseResult, data=GetRequest(id=item_id, version=version))
        response.result = vault_item_adapter.validate_python(response.json["result"])
        return cast(PangeaResponse[VaultItem], response)

    async def get_bulk(
        self,
        filter_: Mapping[str, str],
        *,
        size: int | None = None,
        order: ItemOrder | None = None,
        order_by: ItemOrderBy | None = None,
        last: str | None = None,
    ) -> PangeaResponse[GetBulkResponse]:
        """
        Get bulk

        Retrieve details for multiple Vault items, including keys, secrets,
        tokens, or folders, that match a given filter specification.

        OperationId: vault_post_v2_get_bulk

        Args:
            filter: Filters to customize your search.
            size: Maximum number of items in the response.
            order: Direction for ordering the results.
            order_by: Property by which to order the results.
            last: Internal ID returned in the previous look up response. Used
              for pagination.

        Examples:
            response = await vault.get_bulk({"id": "pvi_..."})
        """
        return await self.request.post(
            "v2/get_bulk",
            GetBulkResponse,
            data=GetBulkRequest(filter=filter_, size=size, order=order, order_by=order_by, last=last),
        )

    async def list(
        self,
        *,
        filter: Optional[Mapping[str, str]] = None,
        size: int = 50,
        order: Optional[ItemOrder] = None,
        order_by: ItemOrderBy | None = None,
        last: str | None = None,
    ) -> PangeaResponse[ListResult]:
        """
        List

        Retrieve a list of secrets, keys and folders, and their associated information.

        OperationId: vault_post_v2_list

        Args:
            filter: A set of filters to help you customize your search.

              Examples:
              - "folder": "/tmp"
              - "tags": "personal"
              - "name__contains": "xxx"
              - "created_at__gt": "2020-02-05T10:00:00Z"

              For metadata, use: "metadata_{key}": "{value}"
            size: Maximum number of items in the response. Default is `50`.
            order: Ordering direction: `asc` or `desc`
            order_by: Property used to order the results. Supported properties: `id`,
                `type`, `created_at`, `algorithm`, `purpose`, `expiration`, `last_rotated`, `next_rotation`,
                `name`, `folder`, `item_state`.
            last: Internal ID returned in the previous look up response. Used
              for pagination.

        Returns:
            A PangeaResponse where a list of secrets or keys
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#list).

        Raises:
            PangeaAPIException: If an API Error happens

        Examples:
            response = await vault.list(
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
        return await self.request.post(
            "v2/list",
            ListResult,
            data=ListRequest(filter=filter, size=size, order=order, order_by=order_by, last=last),
        )

    async def update(
        self,
        item_id: str,
        *,
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        disabled_at: str | None = None,
        enabled: bool | None = None,
        rotation_frequency: str | None = None,
        rotation_state: RequestRotationState = RequestRotationState.INHERITED,
        rotation_grace_period: str | None = None,
    ) -> PangeaResponse[UpdateResult]:
        """
        Update

        Update information associated with a secret, key or folder.

        OperationId: vault_post_v2_update

        Args:
            item_id: The item ID.
            name: The name of this item
            folder: The folder where this item is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            disabled_at: Timestamp indicating when the item will be disabled.
            enabled: True if the item is enabled.
            rotation_frequency: Period of time between item rotations.
            rotation_state: State to which the previous version should transition upon rotation.
            rotation_grace_period: Grace period for the previous version of the Pangea Token.

        Returns:
            A PangeaResponse where the item ID is returned in the
            response.result field. Available response fields can be found in our
            [API documentation](https://pangea.cloud/docs/api/vault#update).

        Raises:
            PangeaAPIException: If an API Error happens

        Examples:
            response = await vault.update(
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
            )
        """
        return await self.request.post(
            "v2/update",
            UpdateResult,
            data=UpdateRequest(
                id=item_id,
                name=name,
                folder=folder,
                metadata=metadata,
                tags=tags,
                disabled_at=disabled_at,
                enabled=enabled,
                rotation_frequency=rotation_frequency,
                rotation_state=rotation_state,
                rotation_grace_period=rotation_grace_period,
            ),
        )

    async def _secret_store(
        self,
        *,
        item_type: Literal["secret", "pangea_token", "pangea_client_secret"] = "secret",
        result_class: type[TResult] = SecretStoreResult,  # type: ignore[assignment]
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        disabled_at: datetime.datetime | None = None,
        **kwargs: Any,
    ) -> PangeaResponse[TResult]:
        return await self.request.post(
            "v2/secret/store",
            result_class,
            data=SecretStoreRequest(
                type=item_type,
                name=name,
                folder=folder,
                metadata=metadata,
                tags=tags,
                disabled_at=disabled_at,
                **kwargs,
            ),
        )

    async def store_secret(
        self,
        secret: str,
        *,
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        disabled_at: datetime.datetime | None = None,
    ) -> PangeaResponse[Secret]:
        """
        Store secret

        Store a secret.

        Args:
            secret: The secret value.
            name: The name of this item.
            folder: The folder where this item is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            disabled_at: Timestamp indicating when the item will be disabled.

        Raises:
            PangeaAPIException: If an API Error happens

        Examples:
            response = await vault.store_secret(secret="foobar")
        """

        return await self._secret_store(
            item_type="secret",
            result_class=Secret,
            secret=secret,
            name=name,
            folder=folder,
            metadata=metadata,
            tags=tags,
            disabled_at=disabled_at,
        )

    async def store_pangea_token(
        self,
        token: str,
        *,
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        disabled_at: datetime.datetime | None = None,
        rotation_frequency: str | None = None,
        rotation_state: RotationState | None = None,
        rotation_grace_period: str | None = None,
    ) -> PangeaResponse[PangeaToken]:
        """
        Store secret

        Store a Pangea token.

        Args:
            token: The Pangea token value.
            name: The name of this item.
            folder: The folder where this item is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            disabled_at: Timestamp indicating when the item will be disabled.

        Raises:
            PangeaAPIException: If an API Error happens

        Examples:
            response = await vault.store_pangea_token(token="foobar")
        """

        return await self._secret_store(
            item_type="pangea_token",
            result_class=PangeaToken,
            token=token,
            name=name,
            folder=folder,
            metadata=metadata,
            tags=tags,
            disabled_at=disabled_at,
            rotation_frequency=rotation_frequency,
            rotation_state=rotation_state,
            rotation_grace_period=rotation_grace_period,
        )

    async def store_pangea_client_secret(
        self,
        client_secret: str,
        client_id: str,
        client_secret_id: str,
        *,
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        disabled_at: datetime.datetime | None = None,
        rotation_frequency: str | None = None,
        rotation_state: RotationState | None = None,
        rotation_grace_period: str | None = None,
    ) -> PangeaResponse[ClientSecret]:
        """
        Store secret

        Store a Pangea client secret.

        Args:
            client_secret: The oauth client secret.
            client_id: The oauth client ID.
            client_secret_id: The oauth client secret ID.
            name: The name of this item.
            folder: The folder where this item is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            disabled_at: Timestamp indicating when the item will be disabled.
            rotation_frequency: Period of time between item rotations.
            rotation_state: State to which the previous version should
              transition upon rotation.
            rotation_grace_period: Grace period for the previous version of the
              Pangea Token.

        Raises:
            PangeaAPIException: If an API Error happens

        Examples:
            response = await vault.store_pangea_client_secret(
                client_secret="foo",
                client_id="bar",
                client_secret_id="baz",
            )
        """

        return await self._secret_store(
            item_type="pangea_client_secret",
            result_class=ClientSecret,
            client_secret=client_secret,
            client_id=client_id,
            client_secret_id=client_secret_id,
            name=name,
            folder=folder,
            metadata=metadata,
            tags=tags,
            disabled_at=disabled_at,
            rotation_frequency=rotation_frequency,
            rotation_state=rotation_state,
            rotation_grace_period=rotation_grace_period,
        )

    async def rotate_secret(
        self,
        item_id: str,
        secret: str,
        *,
        rotation_state: RequestManualRotationState = RequestManualRotationState.DEACTIVATED,
    ) -> PangeaResponse[Secret]:
        """
        Rotate secret

        Rotate a secret.

        Args:
            item_id: The item ID.
            secret: The secret value.
            rotation_state: State to which the previous version should
              transition upon rotation.

        Raises:
            PangeaAPIException: If an API Error happens

        Examples:
            response = await vault.rotate_secret(item_id="foo", secret="bar")
        """

        return await self.request.post(
            "v2/secret/rotate",
            Secret,
            data=SecretRotateRequest(id=item_id, secret=secret, rotation_state=rotation_state),
        )

    async def rotate_pangea_token(
        self,
        item_id: str,
        *,
        rotation_grace_period: str | None = None,
        rotation_state: RequestManualRotationState = RequestManualRotationState.DEACTIVATED,
    ) -> PangeaResponse[PangeaToken]:
        """
        Rotate secret

        Rotate a Pangea token.

        Args:
            item_id: The item ID.
            rotation_grace_period: Grace period for the previous version of the
              Pangea Token.
            rotation_state: State to which the previous version should
              transition upon rotation.

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.rotate_pangea_token(item_id="foo")
        """

        return await self.request.post(
            "v2/secret/rotate",
            PangeaToken,
            data=PangeaTokenRotateRequest(
                id=item_id, rotation_grace_period=rotation_grace_period, rotation_state=rotation_state
            ),
        )

    async def rotate_client_secret(
        self,
        item_id: str,
        *,
        rotation_grace_period: str | None = None,
        rotation_state: RequestManualRotationState = RequestManualRotationState.DEACTIVATED,
    ) -> PangeaResponse[ClientSecret]:
        """
        Rotate secret

        Rotate a client secret.

        Args:
            item_id: The item ID.
            rotation_grace_period: Grace period for the previous version of the
              Pangea Token.
            rotation_state: State to which the previous version should
              transition upon rotation.

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.rotate_client_secret(item_id="foo")
        """

        return await self.request.post(
            "v2/secret/rotate",
            ClientSecret,
            data=ClientSecretRotateRequest(
                id=item_id, rotation_grace_period=rotation_grace_period, rotation_state=rotation_state
            ),
        )

    @overload
    async def generate_key(
        self,
        *,
        key_type: Literal[ItemType.ASYMMETRIC_KEY],
        purpose: Literal[AsymmetricKeyPurpose.SIGNING],
        algorithm: AsymmetricKeySigningAlgorithm,
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        rotation_frequency: str | None = None,
        rotation_state: RequestRotationState | None = RequestRotationState.INHERITED,
        disabled_at: datetime.datetime | None = None,
        exportable: bool = False,
    ) -> PangeaResponse[AsymmetricKey]:
        """
        Generate key

        Generate an asymmetric signing key.

        Args:
            key_type: Key type.
            purpose: The purpose of this key.
            algorithm: The algorithm of the key.
            name: The name of this item.
            folder: The folder where this item is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            rotation_frequency: Period of time between item rotations.
            rotation_state: State to which the previous version should
              transition upon rotation.
            disabled_at: Timestamp indicating when the item will be disabled.
            exportable: Whether the key is exportable or not.

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.generate_key(
                key_type=ItemType.ASYMMETRIC_KEY,
                purpose=AsymmetricKeyPurpose.SIGNING,
                algorithm=AsymmetricKeySigningAlgorithm.ED25519,
            )
        """

    @overload
    async def generate_key(
        self,
        *,
        key_type: Literal[ItemType.ASYMMETRIC_KEY],
        purpose: Literal[AsymmetricKeyPurpose.ENCRYPTION],
        algorithm: AsymmetricKeyEncryptionAlgorithm,
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        rotation_frequency: str | None = None,
        rotation_state: RequestRotationState | None = RequestRotationState.INHERITED,
        disabled_at: datetime.datetime | None = None,
        exportable: bool = False,
    ) -> PangeaResponse[AsymmetricKey]:
        """
        Generate key

        Generate an asymmetric encryption key.

        Args:
            key_type: Key type.
            purpose: The purpose of this key.
            algorithm: The algorithm of the key.
            name: The name of this item.
            folder: The folder where this item is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            rotation_frequency: Period of time between item rotations.
            rotation_state: State to which the previous version should
              transition upon rotation.
            disabled_at: Timestamp indicating when the item will be disabled.
            exportable: Whether the key is exportable or not.

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.generate_key(
                key_type=ItemType.ASYMMETRIC_KEY,
                purpose=AsymmetricKeyPurpose.ENCRYPTION,
                algorithm=AsymmetricKeyEncryptionAlgorithm.RSA_OAEP_2048_SHA1,
            )
        """

    @overload
    async def generate_key(
        self,
        *,
        key_type: Literal[ItemType.ASYMMETRIC_KEY],
        purpose: Literal[AsymmetricKeyPurpose.JWT],
        algorithm: AsymmetricKeyJwtAlgorithm,
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        rotation_frequency: str | None = None,
        rotation_state: RequestRotationState | None = RequestRotationState.INHERITED,
        disabled_at: datetime.datetime | None = None,
        exportable: bool = False,
    ) -> PangeaResponse[AsymmetricKey]:
        """
        Generate key

        Generate an asymmetric JWT key.

        Args:
            key_type: Key type.
            purpose: The purpose of this key.
            algorithm: The algorithm of the key.
            name: The name of this item.
            folder: The folder where this item is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            rotation_frequency: Period of time between item rotations.
            rotation_state: State to which the previous version should
              transition upon rotation.
            disabled_at: Timestamp indicating when the item will be disabled.
            exportable: Whether the key is exportable or not.

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.generate_key(
                key_type=ItemType.ASYMMETRIC_KEY,
                purpose=AsymmetricKeyPurpose.JWT,
                algorithm=AsymmetricKeyJwtAlgorithm.ES512,
            )
        """

    @overload
    async def generate_key(
        self,
        *,
        key_type: Literal[ItemType.ASYMMETRIC_KEY],
        purpose: Literal[AsymmetricKeyPurpose.PKI],
        algorithm: AsymmetricKeyPkiAlgorithm,
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        rotation_frequency: str | None = None,
        rotation_state: RequestRotationState | None = RequestRotationState.INHERITED,
        disabled_at: datetime.datetime | None = None,
        exportable: bool = False,
    ) -> PangeaResponse[AsymmetricKey]:
        """
        Generate key

        Generate an asymmetric PKI key.

        Args:
            key_type: Key type.
            purpose: The purpose of this key.
            algorithm: The algorithm of the key.
            name: The name of this item.
            folder: The folder where this item is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            rotation_frequency: Period of time between item rotations.
            rotation_state: State to which the previous version should
              transition upon rotation.
            disabled_at: Timestamp indicating when the item will be disabled.
            exportable: Whether the key is exportable or not.

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.generate_key(
                key_type=ItemType.ASYMMETRIC_KEY,
                purpose=AsymmetricKeyPurpose.PKI,
                algorithm=AsymmetricKeyPkiAlgorithm.ED25519,
            )
        """

    @overload
    async def generate_key(
        self,
        *,
        key_type: Literal[ItemType.ASYMMETRIC_KEY],
        purpose: AsymmetricKeyPurpose,
        algorithm: AsymmetricKeyAlgorithm,
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        rotation_frequency: str | None = None,
        rotation_state: RequestRotationState | None = RequestRotationState.INHERITED,
        disabled_at: datetime.datetime | None = None,
        exportable: bool = False,
    ) -> PangeaResponse[AsymmetricKey]:
        """
        Generate key

        Generate an asymmetric key.

        Args:
            key_type: Key type.
            purpose: The purpose of this key.
            algorithm: The algorithm of the key.
            name: The name of this item.
            folder: The folder where this item is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            rotation_frequency: Period of time between item rotations.
            rotation_state: State to which the previous version should
              transition upon rotation.
            disabled_at: Timestamp indicating when the item will be disabled.
            exportable: Whether the key is exportable or not.

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.generate_key(
                key_type=ItemType.ASYMMETRIC_KEY,
                purpose=AsymmetricKeyPurpose.PKI,
                algorithm=AsymmetricKeyPkiAlgorithm.ED25519,
            )
        """

    @overload
    async def generate_key(
        self,
        *,
        key_type: Literal[ItemType.SYMMETRIC_KEY],
        purpose: Literal[SymmetricKeyPurpose.ENCRYPTION],
        algorithm: SymmetricKeyEncryptionAlgorithm,
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        rotation_frequency: str | None = None,
        rotation_state: RequestRotationState | None = RequestRotationState.INHERITED,
        disabled_at: datetime.datetime | None = None,
        exportable: bool = False,
    ) -> PangeaResponse[SymmetricKey]:
        """
        Generate key

        Generate a symmetric encryption key.

        Args:
            key_type: Key type.
            purpose: The purpose of this key.
            algorithm: The algorithm of the key.
            name: The name of this item.
            folder: The folder where this item is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            rotation_frequency: Period of time between item rotations.
            rotation_state: State to which the previous version should
              transition upon rotation.
            disabled_at: Timestamp indicating when the item will be disabled.
            exportable: Whether the key is exportable or not.

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.generate_key(
                key_type=ItemType.SYMMETRIC_KEY,
                purpose=SymmetricKeyPurpose.ENCRYPTION,
                algorithm=SymmetricKeyEncryptionAlgorithm.AES_CFB_128,
            )
        """

    @overload
    async def generate_key(
        self,
        *,
        key_type: Literal[ItemType.SYMMETRIC_KEY],
        purpose: Literal[SymmetricKeyPurpose.JWT],
        algorithm: SymmetricKeyJwtAlgorithm,
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        rotation_frequency: str | None = None,
        rotation_state: RequestRotationState | None = RequestRotationState.INHERITED,
        disabled_at: datetime.datetime | None = None,
        exportable: bool = False,
    ) -> PangeaResponse[SymmetricKey]:
        """
        Generate key

        Generate a symmetric JWT key.

        Args:
            key_type: Key type.
            purpose: The purpose of this key.
            algorithm: The algorithm of the key.
            name: The name of this item.
            folder: The folder where this item is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            rotation_frequency: Period of time between item rotations.
            rotation_state: State to which the previous version should
              transition upon rotation.
            disabled_at: Timestamp indicating when the item will be disabled.
            exportable: Whether the key is exportable or not.

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.generate_key(
                key_type=ItemType.SYMMETRIC_KEY,
                purpose=SymmetricKeyPurpose.JWT,
                algorithm=SymmetricKeyJwtAlgorithm.HS512,
            )
        """

    @overload
    async def generate_key(
        self,
        *,
        key_type: Literal[ItemType.SYMMETRIC_KEY],
        purpose: Literal[SymmetricKeyPurpose.FPE],
        algorithm: SymmetricKeyFpeAlgorithm,
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        rotation_frequency: str | None = None,
        rotation_state: RequestRotationState | None = RequestRotationState.INHERITED,
        disabled_at: datetime.datetime | None = None,
        exportable: bool = False,
    ) -> PangeaResponse[SymmetricKey]:
        """
        Generate key

        Generate a symmetric FPE key.

        Args:
            key_type: Key type.
            purpose: The purpose of this key.
            algorithm: The algorithm of the key.
            name: The name of this item.
            folder: The folder where this item is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            rotation_frequency: Period of time between item rotations.
            rotation_state: State to which the previous version should
              transition upon rotation.
            disabled_at: Timestamp indicating when the item will be disabled.
            exportable: Whether the key is exportable or not.

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.generate_key(
                key_type=ItemType.SYMMETRIC_KEY,
                purpose=SymmetricKeyPurpose.FPE,
                algorithm=SymmetricKeyFpeAlgorithm.AES_FF3_1_256_BETA,
            )
        """

    @overload
    async def generate_key(
        self,
        *,
        key_type: Literal[ItemType.SYMMETRIC_KEY],
        purpose: SymmetricKeyPurpose,
        algorithm: SymmetricKeyAlgorithm,
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        rotation_frequency: str | None = None,
        rotation_state: RequestRotationState | None = RequestRotationState.INHERITED,
        disabled_at: datetime.datetime | None = None,
        exportable: bool = False,
    ) -> PangeaResponse[SymmetricKey]:
        """
        Generate key

        Generate a symmetric key.

        Args:
            key_type: Key type.
            purpose: The purpose of this key.
            algorithm: The algorithm of the key.
            name: The name of this item.
            folder: The folder where this item is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            rotation_frequency: Period of time between item rotations.
            rotation_state: State to which the previous version should
              transition upon rotation.
            disabled_at: Timestamp indicating when the item will be disabled.
            exportable: Whether the key is exportable or not.

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.generate_key(
                key_type=ItemType.SYMMETRIC_KEY,
                purpose=SymmetricKeyPurpose.FPE,
                algorithm=SymmetricKeyFpeAlgorithm.AES_FF3_1_256_BETA,
            )
        """

    async def generate_key(
        self,
        *,
        key_type: Literal[ItemType.ASYMMETRIC_KEY, ItemType.SYMMETRIC_KEY],
        purpose: SymmetricKeyPurpose | AsymmetricKeyPurpose,
        algorithm: AsymmetricKeyAlgorithm | SymmetricKeyAlgorithm,
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        rotation_frequency: str | None = None,
        rotation_state: RequestRotationState | None = RequestRotationState.INHERITED,
        disabled_at: datetime.datetime | None = None,
        exportable: bool = False,
    ) -> PangeaResponse[Any]:
        """
        Generate key

        Generate a key.

        Args:
            key_type: Key type.
            purpose: The purpose of this key.
            algorithm: The algorithm of the key.
            name: The name of this item.
            folder: The folder where this item is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            rotation_frequency: Period of time between item rotations.
            rotation_state: State to which the previous version should
              transition upon rotation.
            disabled_at: Timestamp indicating when the item will be disabled.
            exportable: Whether the key is exportable or not.

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.generate_key(
                key_type=ItemType.SYMMETRIC_KEY,
                purpose=SymmetricKeyPurpose.FPE,
                algorithm=SymmetricKeyFpeAlgorithm.AES_FF3_1_256_BETA,
            )
        """

        return await self.request.post(
            "v2/key/generate",
            AsymmetricKey if key_type == ItemType.ASYMMETRIC_KEY else SymmetricKey,
            data=CommonGenerateRequest(
                type=key_type,
                purpose=purpose,
                algorithm=algorithm,
                name=name,
                folder=folder,
                metadata=metadata,
                tags=tags,
                rotation_frequency=rotation_frequency,
                rotation_state=rotation_state,
                disabled_at=disabled_at,
                exportable=exportable,
            ),
        )

    @overload
    async def store_key(
        self,
        *,
        key_type: Literal[ItemType.ASYMMETRIC_KEY],
        purpose: Literal[AsymmetricKeyPurpose.SIGNING],
        algorithm: AsymmetricKeySigningAlgorithm,
        public_key: str,
        private_key: str,
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        rotation_frequency: str | None = None,
        rotation_state: RequestRotationState | None = RequestRotationState.INHERITED,
        disabled_at: datetime.datetime | None = None,
        exportable: bool = False,
    ) -> PangeaResponse[AsymmetricKey]:
        """
        Store key

        Import an asymmetric signing key.

        Args:
            key_type: Key type.
            purpose: The purpose of this key.
            algorithm: The algorithm of the key.
            public_key: The public key (in PEM format).
            private_key: The private key (in PEM format).
            name: The name of this item.
            folder: The folder where this item is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            rotation_frequency: Period of time between item rotations.
            rotation_state: State to which the previous version should
              transition upon rotation.
            disabled_at: Timestamp indicating when the item will be disabled.
            exportable: Whether the key is exportable or not.

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.store_key(
                key_type=ItemType.ASYMMETRIC_KEY,
                purpose=AsymmetricKeyPurpose.SIGNING,
                algorithm=AsymmetricKeySigningAlgorithm.ED25519,
            )
        """

    @overload
    async def store_key(
        self,
        *,
        key_type: Literal[ItemType.ASYMMETRIC_KEY],
        purpose: Literal[AsymmetricKeyPurpose.ENCRYPTION],
        algorithm: AsymmetricKeyEncryptionAlgorithm,
        public_key: str,
        private_key: str,
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        rotation_frequency: str | None = None,
        rotation_state: RequestRotationState | None = RequestRotationState.INHERITED,
        disabled_at: datetime.datetime | None = None,
        exportable: bool = False,
    ) -> PangeaResponse[AsymmetricKey]:
        """
        Store key

        Import an asymmetric encryption key.

        Args:
            key_type: Key type.
            purpose: The purpose of this key.
            algorithm: The algorithm of the key.
            public_key: The public key (in PEM format).
            private_key: The private key (in PEM format).
            name: The name of this item.
            folder: The folder where this item is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            rotation_frequency: Period of time between item rotations.
            rotation_state: State to which the previous version should
              transition upon rotation.
            disabled_at: Timestamp indicating when the item will be disabled.
            exportable: Whether the key is exportable or not.

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.store_key(
                key_type=ItemType.ASYMMETRIC_KEY,
                purpose=AsymmetricKeyPurpose.ENCRYPTION,
                algorithm=AsymmetricKeyEncryptionAlgorithm.RSA_OAEP_2048_SHA1,
            )
        """

    @overload
    async def store_key(
        self,
        *,
        key_type: Literal[ItemType.ASYMMETRIC_KEY],
        purpose: Literal[AsymmetricKeyPurpose.JWT],
        algorithm: AsymmetricKeyJwtAlgorithm,
        public_key: str,
        private_key: str,
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        rotation_frequency: str | None = None,
        rotation_state: RequestRotationState | None = RequestRotationState.INHERITED,
        disabled_at: datetime.datetime | None = None,
        exportable: bool = False,
    ) -> PangeaResponse[AsymmetricKey]:
        """
        Store key

        Import an asymmetric JWT key.

        Args:
            key_type: Key type.
            purpose: The purpose of this key.
            algorithm: The algorithm of the key.
            public_key: The public key (in PEM format).
            private_key: The private key (in PEM format).
            name: The name of this item.
            folder: The folder where this item is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            rotation_frequency: Period of time between item rotations.
            rotation_state: State to which the previous version should
              transition upon rotation.
            disabled_at: Timestamp indicating when the item will be disabled.
            exportable: Whether the key is exportable or not.

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.store_key(
                key_type=ItemType.ASYMMETRIC_KEY,
                purpose=AsymmetricKeyPurpose.JWT,
                algorithm=AsymmetricKeyJwtAlgorithm.ES512,
            )
        """

    @overload
    async def store_key(
        self,
        *,
        key_type: Literal[ItemType.ASYMMETRIC_KEY],
        purpose: Literal[AsymmetricKeyPurpose.PKI],
        algorithm: AsymmetricKeyPkiAlgorithm,
        public_key: str,
        private_key: str,
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        rotation_frequency: str | None = None,
        rotation_state: RequestRotationState | None = RequestRotationState.INHERITED,
        disabled_at: datetime.datetime | None = None,
        exportable: bool = False,
    ) -> PangeaResponse[AsymmetricKey]:
        """
        Store key

        Import an asymmetric PKI key.

        Args:
            key_type: Key type.
            purpose: The purpose of this key.
            algorithm: The algorithm of the key.
            public_key: The public key (in PEM format).
            private_key: The private key (in PEM format).
            name: The name of this item.
            folder: The folder where this item is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            rotation_frequency: Period of time between item rotations.
            rotation_state: State to which the previous version should
              transition upon rotation.
            disabled_at: Timestamp indicating when the item will be disabled.
            exportable: Whether the key is exportable or not.

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.store_key(
                key_type=ItemType.ASYMMETRIC_KEY,
                purpose=AsymmetricKeyPurpose.PKI,
                algorithm=AsymmetricKeyPkiAlgorithm.ED25519,
            )
        """

    @overload
    async def store_key(
        self,
        *,
        key_type: Literal[ItemType.SYMMETRIC_KEY],
        purpose: Literal[SymmetricKeyPurpose.ENCRYPTION],
        algorithm: SymmetricKeyEncryptionAlgorithm,
        key: str,
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        rotation_frequency: str | None = None,
        rotation_state: RequestRotationState | None = RequestRotationState.INHERITED,
        disabled_at: datetime.datetime | None = None,
        exportable: bool = False,
    ) -> PangeaResponse[SymmetricKey]:
        """
        Store key

        Import a symmetric encryption key.

        Args:
            key_type: Key type.
            purpose: The purpose of this key.
            algorithm: The algorithm of the key.
            key: The key material.
            name: The name of this item.
            folder: The folder where this item is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            rotation_frequency: Period of time between item rotations.
            rotation_state: State to which the previous version should
              transition upon rotation.
            disabled_at: Timestamp indicating when the item will be disabled.
            exportable: Whether the key is exportable or not.

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.store_key(
                key_type=ItemType.SYMMETRIC_KEY,
                purpose=SymmetricKeyPurpose.ENCRYPTION,
                algorithm=SymmetricKeyEncryptionAlgorithm.AES_CFB_128,
            )
        """

    @overload
    async def store_key(
        self,
        *,
        key_type: Literal[ItemType.SYMMETRIC_KEY],
        purpose: Literal[SymmetricKeyPurpose.JWT],
        algorithm: SymmetricKeyJwtAlgorithm,
        key: str,
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        rotation_frequency: str | None = None,
        rotation_state: RequestRotationState | None = RequestRotationState.INHERITED,
        disabled_at: datetime.datetime | None = None,
        exportable: bool = False,
    ) -> PangeaResponse[SymmetricKey]:
        """
        Store key

        Import a symmetric JWT key.

        Args:
            key_type: Key type.
            purpose: The purpose of this key.
            algorithm: The algorithm of the key.
            key: The key material.
            name: The name of this item.
            folder: The folder where this item is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            rotation_frequency: Period of time between item rotations.
            rotation_state: State to which the previous version should
              transition upon rotation.
            disabled_at: Timestamp indicating when the item will be disabled.
            exportable: Whether the key is exportable or not.

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.store_key(
                key_type=ItemType.SYMMETRIC_KEY,
                purpose=SymmetricKeyPurpose.JWT,
                algorithm=SymmetricKeyJwtAlgorithm.HS512,
            )
        """

    @overload
    async def store_key(
        self,
        *,
        key_type: Literal[ItemType.SYMMETRIC_KEY],
        purpose: Literal[SymmetricKeyPurpose.FPE],
        algorithm: SymmetricKeyFpeAlgorithm,
        key: str,
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        rotation_frequency: str | None = None,
        rotation_state: RequestRotationState | None = RequestRotationState.INHERITED,
        disabled_at: datetime.datetime | None = None,
        exportable: bool = False,
    ) -> PangeaResponse[SymmetricKey]:
        """
        Store key

        Import a symmetric FPE key.

        Args:
            key_type: Key type.
            purpose: The purpose of this key.
            algorithm: The algorithm of the key.
            key: The key material.
            name: The name of this item.
            folder: The folder where this item is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            rotation_frequency: Period of time between item rotations.
            rotation_state: State to which the previous version should
              transition upon rotation.
            disabled_at: Timestamp indicating when the item will be disabled.
            exportable: Whether the key is exportable or not.

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.store_key(
                key_type=ItemType.SYMMETRIC_KEY,
                purpose=SymmetricKeyPurpose.FPE,
                algorithm=SymmetricKeyFpeAlgorithm.AES_FF3_1_256_BETA,
            )
        """

    async def store_key(
        self,
        *,
        key_type: Literal[ItemType.ASYMMETRIC_KEY, ItemType.SYMMETRIC_KEY],
        purpose: SymmetricKeyPurpose | AsymmetricKeyPurpose,
        algorithm: (
            AsymmetricKeySigningAlgorithm
            | AsymmetricKeyEncryptionAlgorithm
            | AsymmetricKeyJwtAlgorithm
            | AsymmetricKeyPkiAlgorithm
            | SymmetricKeyEncryptionAlgorithm
            | SymmetricKeyJwtAlgorithm
            | SymmetricKeyFpeAlgorithm
        ),
        public_key: str | None = None,
        private_key: str | None = None,
        key: str | None = None,
        name: str | None = None,
        folder: str | None = None,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        rotation_frequency: str | None = None,
        rotation_state: RequestRotationState | None = RequestRotationState.INHERITED,
        disabled_at: datetime.datetime | None = None,
        exportable: bool = False,
    ) -> PangeaResponse[Any]:
        """
        Store key

        Import a key.

        Args:
            key_type: Key type.
            purpose: The purpose of this key.
            algorithm: The algorithm of the key.
            public_key: The public key (in PEM format).
            private_key: The private key (in PEM format).
            key: The key material.
            name: The name of this item.
            folder: The folder where this item is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            rotation_frequency: Period of time between item rotations.
            rotation_state: State to which the previous version should
              transition upon rotation.
            disabled_at: Timestamp indicating when the item will be disabled.
            exportable: Whether the key is exportable or not.

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.store_key(
                key_type=ItemType.SYMMETRIC_KEY,
                purpose=SymmetricKeyPurpose.FPE,
                algorithm=SymmetricKeyFpeAlgorithm.AES_FF3_1_256_BETA,
            )
        """

        return await self.request.post(
            "v2/key/store",
            AsymmetricKey if key_type == ItemType.ASYMMETRIC_KEY else SymmetricKey,
            data=KeyStoreRequest(
                type=key_type,
                purpose=purpose,
                algorithm=algorithm,
                public_key=public_key,
                private_key=private_key,
                key=key,
                name=name,
                folder=folder,
                metadata=metadata,
                tags=tags,
                rotation_frequency=rotation_frequency,
                rotation_state=rotation_state,
                disabled_at=disabled_at,
                exportable=exportable,
            ),
        )

    @overload
    async def rotate_key(
        self,
        key_id: str,
        *,
        key_type: Literal[ItemType.ASYMMETRIC_KEY],
        rotation_state: RequestManualRotationState = RequestManualRotationState.DEACTIVATED,
        public_key: str | None = None,
        private_key: str | None = None,
    ) -> PangeaResponse[AsymmetricKey]:
        """
        Rotate key

        Manually rotate an asymmetric key.

        Args:
            key_id: The ID of the key.
            key_type: Key type.
            rotation_state: State to which the previous version should
              transition upon rotation.
            public_key: The public key (in PEM format).
            private_key: The private key (in PEM format).

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.rotate_key("pvi_...", key_type=ItemType.ASYMMETRIC_KEY)
        """

    @overload
    async def rotate_key(
        self,
        key_id: str,
        *,
        key_type: Literal[ItemType.SYMMETRIC_KEY],
        rotation_state: RequestManualRotationState = RequestManualRotationState.DEACTIVATED,
        key: str | None = None,
    ) -> PangeaResponse[SymmetricKey]:
        """
        Rotate key

        Manually rotate a symmetric key.

        Args:
            key_id: The ID of the key.
            key_type: Key type.
            rotation_state: State to which the previous version should
              transition upon rotation.
            key: The key material.

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.rotate_key("pvi_...", key_type=ItemType.SYMMETRIC_KEY)
        """

    async def rotate_key(
        self,
        key_id: str,
        *,
        key_type: Literal[ItemType.ASYMMETRIC_KEY, ItemType.SYMMETRIC_KEY],
        rotation_state: RequestManualRotationState = RequestManualRotationState.DEACTIVATED,
        public_key: str | None = None,
        private_key: str | None = None,
        key: str | None = None,
    ) -> PangeaResponse[Any]:
        """
        Rotate key

        Manually rotate an asymmetric or symmetric key.

        Args:
            key_id: The ID of the key.
            key_type: Key type.
            rotation_state: State to which the previous version should
              transition upon rotation.
            public_key: The public key (in PEM format).
            private_key: The private key (in PEM format).
            key: The key material.

        Raises:
            PangeaAPIException: If an API Error happens.

        Examples:
            response = await vault.rotate_key("pvi_...", key_type=ItemType.SYMMETRIC_KEY)
        """

        return await self.request.post(
            "v2/key/rotate",
            AsymmetricKey if key_type == ItemType.ASYMMETRIC_KEY else SymmetricKey,
            data=KeyRotateRequest(
                id=key_id,
                public_key=public_key,
                private_key=private_key,
                key=key,
                rotation_state=rotation_state,
            ),
        )

    async def encrypt(
        self, item_id: str, plain_text: str, *, version: int | None = None, additional_data: str | None = None
    ) -> PangeaResponse[EncryptResult]:
        """
        Encrypt

        Encrypt a message using a key.

        OperationId: vault_post_v2_key_encrypt

        Args:
            item_id: The item ID.
            plain_text: A message to be encrypted (in base64).
            version: The item version.
            additional_data: User provided authentication data.

        Returns:
            A PangeaResponse where the encrypted message in base64 is returned
            in the response.result field. Available response fields can be found
            in our [API documentation](https://pangea.cloud/docs/api/vault#encrypt).

        Raises:
            PangeaAPIException: If an API Error happens

        Examples:
            response = await vault.encrypt(
                id="pvi_p6g5i3gtbvqvc3u6zugab6qs6r63tqf5",
                plain_text="lJkk0gCLux+Q+rPNqLPEYw==",
                version=1,
            )
        """
        return await self.request.post(
            "v2/encrypt",
            EncryptResult,
            data=EncryptRequest(id=item_id, plain_text=plain_text, version=version, additional_data=additional_data),
        )

    async def decrypt(
        self, item_id: str, cipher_text: str, *, version: int | None = None, additional_data: str | None = None
    ) -> PangeaResponse[DecryptResult]:
        """
        Decrypt

        Decrypt a message using a key.

        OperationId: vault_post_v2_key_decrypt

        Args:
            item_id: The item ID.
            cipher_text: A message encrypted by Vault (in base64).
            version: The item version.
            additional_data: User provided authentication data.

        Returns:
            A PangeaResponse where the decrypted message in base64 is returned
            in the response.result field. Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#decrypt).

        Raises:
            PangeaAPIException: If an API Error happens

        Examples:
            response = await vault.decrypt(
                id="pvi_p6g5i3gtbvqvc3u6zugab6qs6r63tqf5",
                cipher_text="lJkk0gCLux+Q+rPNqLPEYw==",
                version=1,
            )
        """
        return await self.request.post(
            "v2/decrypt",
            DecryptResult,
            data=DecryptRequest(id=item_id, cipher_text=cipher_text, version=version, additional_data=additional_data),
        )

    async def sign(self, item_id: str, message: str, *, version: int | None = None) -> PangeaResponse[SignResult]:
        """
        Sign

        Sign a message using a key

        OperationId: vault_post_v2_sign

        Args:
            id: The item ID.
            message: The message to be signed, in base64.
            version: The item version.

        Returns:
            A PangeaResponse where the signature of the message in base64 is
            returned in the response.result field. Available response fields can
            be found in our [API documentation](https://pangea.cloud/docs/api/vault#sign).

        Raises:
            PangeaAPIException: If an API Error happens

        Examples:
            response = await vault.sign(
                id="pvi_p6g5i3gtbvqvc3u6zugab6qs6r63tqf5",
                message="lJkk0gCLux+Q+rPNqLPEYw==",
                version=1,
            )
        """
        return await self.request.post(
            "v2/sign", SignResult, data=SignRequest(id=item_id, message=message, version=version)
        )

    async def verify(
        self, item_id: str, message: str, signature: str, *, version: int | None = None
    ) -> PangeaResponse[VerifyResult]:
        """
        Verify

        Verify a signature using a key.

        OperationId: vault_post_v2_key_verify

        Args:
            id: The item ID.
            message: A message to be verified (in base64).
            signature: The message signature (in base64).
            version: The item version.

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the signature is valid
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#verify).

        Examples:
            response = await vault.verify(
                id="pvi_p6g5i3gtbvqvc3u6zugab6qs6r63tqf5",
                message="lJkk0gCLux+Q+rPNqLPEYw==",
                signature="FfWuT2Mq/+cxa7wIugfhzi7ktZxVf926idJNgBDCysF/knY9B7M6wxqHMMPDEBs86D8OsEGuED21y3J7IGOpCQ==",
                version=1,
            )
        """
        return await self.request.post(
            "v2/verify",
            VerifyResult,
            data=VerifyRequest(
                id=item_id,
                message=message,
                signature=signature,
                version=version,
            ),
        )

    async def jwt_verify(self, jws: str) -> PangeaResponse[JWTVerifyResult]:
        """
        JWT Verify

        Verify the signature of a JSON Web Token (JWT).

        OperationId: vault_post_v2_key_verify_jwt

        Args:
            jws: The signed JSON Web Token (JWS).

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the signature is valid
                is returned in the response.result field.
                Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/vault#verify-jwt).

        Examples:
            response = await vault.jwt_verify(jws="ewogICJhbGciO...")
        """
        return await self.request.post("v2/jwt/verify", JWTVerifyResult, data=JWTVerifyRequest(jws=jws))

    async def jwt_sign(self, item_id: str, payload: str) -> PangeaResponse[JWTSignResult]:
        """
        JWT Sign

        Sign a JSON Web Token (JWT) using a key.

        OperationId: vault_post_v2_jwt_sign

        Args:
            id: The item ID.
            payload: The JWT payload (in JSON).

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the signed JSON Web Token (JWS) is returned
            in the response.result field. Available response fields can be found
            in our [API documentation](https://pangea.cloud/docs/api/vault#sign-a-jwt).

        Examples:
            response = await vault.jwt_sign(
                id="pvi_p6g5i3gtbvqvc3u6zugab6qs6r63tqf5",
                payload="{\\"sub\\": \\"1234567890\\",\\"name\\": \\"John Doe\\",\\"admin\\": true}"
            )
        """
        return await self.request.post("v2/jwt/sign", JWTSignResult, data=JWTSignRequest(id=item_id, payload=payload))

    async def jwk_get(self, item_id: str, *, version: str | None = None) -> PangeaResponse[JWKGetResult]:
        """
        JWT Retrieve

        Retrieve a key in JWK format.

        OperationId: vault_post_v2_jwk_get

        Args:
            id: The item ID
            version: The key version(s).
              - `all` for all versions
              - `num` for a specific version
              - `-num` for the `num` latest versions
        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the JSON Web Key Set (JWKS) object is
            returned in the response.result field. Available response fields can
            be found in our [API documentation](https://pangea.cloud/docs/api/vault#retrieve-jwk).

        Examples:
            response = await vault.jwk_get("pvi_p6g5i3gtbvqvc3u6zugab6qs6r63tqf5")
        """
        return await self.request.post("v2/jwk/get", JWKGetResult, data=JWKGetRequest(id=item_id, version=version))

    async def state_change(
        self,
        item_id: str,
        state: ItemVersionState,
        *,
        version: int | None = None,
        destroy_period: str | None = None,
    ) -> PangeaResponse[VaultItem]:
        """
        State change

        Change the state of a specific version of a secret or key.

        OperationId: vault_post_v2_state_change

        Args:
            item_id: The item ID.
            state: The new state of the item version.
            version: The item version.
            destroy_period: Period of time for the destruction of a compromised
              key. Only valid if state=`compromised`.

        Returns:
            A PangeaResponse where the state change object is returned in the
            response.result field. Available response fields can be found in our
            [API documentation](https://pangea.cloud/docs/api/vault#change-state).

        Raises:
            PangeaAPIException: If an API Error happens

        Examples:
            response = await vault.state_change(
                id="pvi_p6g5i3gtbvqvc3u6zugab6qs6r63tqf5",
                state=ItemVersionState.DEACTIVATED,
            )
        """
        response = await self.request.post(
            "v2/state/change",
            PangeaResponseResult,
            data=StateChangeRequest(id=item_id, state=state, version=version, destroy_period=destroy_period),
        )
        response.result = vault_item_adapter.validate_python(response.json["result"])
        return cast(PangeaResponse[VaultItem], response)

    async def folder_create(
        self,
        name: str,
        folder: str,
        *,
        metadata: Metadata | None = None,
        tags: Tags | None = None,
        rotation_frequency: str | None = None,
        rotation_state: RequestRotationState = RequestRotationState.INHERITED,
        rotation_grace_period: str | None = None,
        disabled_at: datetime.datetime | None = None,
    ) -> PangeaResponse[FolderCreateResult]:
        """
        Create

        Creates a folder.

        OperationId: vault_post_v2_folder_create

        Args:
            name: The name of this folder.
            folder: The parent folder where this folder is stored.
            metadata: User-provided metadata.
            tags: A list of user-defined tags.
            rotation_frequency: Period of time between item rotations.
            rotation_state: State to which the previous version should
              transition upon rotation.
            rotation_grace_period: Grace period for the previous version.
            disabled_at: Timestamp indicating when the item will be disabled.

        Returns: The created folder object.

        Raises:
            PangeaAPIException: If an API Error happens

        Examples:
            response = await vault.folder_create(
                name="folder_name",
                folder="parent/folder/name",
            )
        """
        return await self.request.post(
            "v2/folder/create",
            FolderCreateResult,
            data=FolderCreateRequest(
                name=name,
                folder=folder,
                metadata=metadata,
                tags=tags,
                rotation_frequency=rotation_frequency,
                rotation_state=rotation_state,
                rotation_grace_period=rotation_grace_period,
                disabled_at=disabled_at,
            ),
        )

    async def encrypt_structured(
        self,
        key_id: str,
        structured_data: TDict,
        filter_expr: str,
        *,
        version: int | None = None,
        additional_data: str | None = None,
    ) -> PangeaResponse[EncryptStructuredResult[TDict]]:
        """
        Encrypt structured

        Encrypt parts of a JSON object.

        OperationId: vault_post_v2_encrypt_structured

        Args:
            key_id: The ID of the key to use.
            structured_data: Structured data for applying bulk operations.
            filter_expr: A filter expression.
            version: The item version. Defaults to the current version.
            additional_data: User provided authentication data.

        Returns:
            A `PangeaResponse` where the encrypted object is returned in the
            `response.result` field. Available response fields can be found in
            our [API documentation](https://pangea.cloud/docs/api/vault#encrypt-structured).

        Raises:
            PangeaAPIException: If an API error happens.

        Examples:
            data = {"field1": [1, 2, "true", "false"], "field2": "data2"}
            response = await vault.encrypt_structured(
                id="pvi_[...]",
                structured_data=data,
                filter="$.field1[2:4]"
            )
        """

        data: EncryptStructuredRequest[TDict] = EncryptStructuredRequest(
            id=key_id,
            structured_data=structured_data,
            filter=filter_expr,
            version=version,
            additional_data=additional_data,
        )
        return await self.request.post(
            "v2/encrypt_structured",
            EncryptStructuredResult,
            data=data.model_dump(exclude_none=True),
        )

    async def decrypt_structured(
        self,
        key_id: str,
        structured_data: TDict,
        filter_expr: str,
        *,
        version: int | None = None,
        additional_data: str | None = None,
    ) -> PangeaResponse[EncryptStructuredResult[TDict]]:
        """
        Decrypt structured

        Decrypt parts of a JSON object.

        OperationId: vault_post_v2_decrypt_structured

        Args:
            id: The ID of the key to use.
            structured_data: Structured data for applying bulk operations.
            filter: A filter expression.
            version: The item version. Defaults to the current version.
            additional_data: User provided authentication data.

        Raises:
            PangeaAPIException: If an API error happens.

        Returns:
            A `PangeaResponse` where the decrypted object is returned in the
            `response.result` field. Available response fields can be found in
            our [API documentation](https://pangea.cloud/docs/api/vault#decrypt-structured).

        Examples:
            data = {"field1": [1, 2, "kxcbC9E9IlgVaSCChPWUMgUC3ko=", "6FfI/LCzatLRLNAc8SuBK/TDnGxp"], "field2": "data2"}
            response = await vault.decrypt_structured(
                id="pvi_[...]",
                structured_data=data,
                filter="$.field1[2:4]"
            )
        """

        data: EncryptStructuredRequest[TDict] = EncryptStructuredRequest(
            id=key_id,
            structured_data=structured_data,
            filter=filter_expr,
            version=version,
            additional_data=additional_data,
        )
        return await self.request.post(
            "v2/decrypt_structured",
            EncryptStructuredResult,
            data=data.model_dump(exclude_none=True),
        )

    async def encrypt_transform(
        self,
        item_id: str,
        plain_text: str,
        alphabet: TransformAlphabet,
        *,
        tweak: str | None = None,
        version: int | None = None,
    ) -> PangeaResponse[EncryptTransformResult]:
        """
        Encrypt transform

        Encrypt using a format-preserving algorithm (FPE).

        OperationId: vault_post_v2_encrypt_transform

        Args:
            item_id: The item ID.
            plain_text: A message to be encrypted.
            alphabet: Set of characters to use for format-preserving encryption (FPE).
            tweak: User provided tweak string. If not provided, a random string
              will be generated and returned.
            version: The item version. Defaults to the current version.

        Raises:
            PangeaAPIException: If an API error happens.

        Returns:
            A `PangeaResponse` containing the encrypted message.

        Examples:
            await vault.encrypt_transform(
                id="pvi_[...]",
                plain_text="message to encrypt",
                alphabet=TransformAlphabet.ALPHANUMERIC,
                tweak="MTIzMTIzMT==",
            )
        """

        return await self.request.post(
            "v2/encrypt_transform",
            EncryptTransformResult,
            data=EncryptTransformRequest(
                id=item_id,
                plain_text=plain_text,
                tweak=tweak,
                alphabet=alphabet,
                version=version,
            ),
        )

    async def decrypt_transform(
        self, item_id: str, cipher_text: str, tweak: str, alphabet: TransformAlphabet, *, version: int | None = None
    ) -> PangeaResponse[DecryptTransformResult]:
        """
        Decrypt transform

        Decrypt using a format-preserving algorithm (FPE).

        OperationId: vault_post_v2_decrypt_transform

        Args:
            id: The item ID.
            cipher_text: A message encrypted by Vault.
            tweak: User provided tweak string.
            alphabet: Set of characters to use for format-preserving encryption (FPE).
            version: The item version. Defaults to the current version.

        Returns:
            A `PangeaResponse` containing the decrypted message.

        Raises:
            PangeaAPIException: If an API error happens.

        Examples:
            await vault.decrypt_transform(
                id="pvi_[...]",
                cipher_text="encrypted message",
                tweak="MTIzMTIzMT==",
                alphabet=TransformAlphabet.ALPHANUMERIC,
            )
        """

        return await self.request.post(
            "v2/decrypt_transform",
            DecryptTransformResult,
            data=DecryptTransformRequest(
                id=item_id, cipher_text=cipher_text, tweak=tweak, alphabet=alphabet, version=version
            ),
        )

    async def export(
        self,
        item_id: str,
        *,
        version: int | None = None,
        kem_password: str | None = None,
        asymmetric_public_key: str | None = None,
        asymmetric_algorithm: ExportEncryptionAlgorithm | None = None,
    ) -> PangeaResponse[ExportResult]:
        """
        Export

        Export a symmetric or asymmetric key.

        OperationId: vault_post_v2_export

        Args:
            item_id: The item ID.
            version: The item version.
            kem_password: This is the password that will be used along with a
              salt to derive the symmetric key that is used to encrypt the
              exported key material.
            asymmetric_public_key: Public key in pem format used to encrypt
              exported key(s).
            asymmetric_algorithm: The algorithm of the public key.

        Returns:
            A `PangeaResponse` where the exported key is returned in the
            `response.result` field. Available response fields can be found in
            our [API documentation](https://pangea.cloud/docs/api/vault#export).

        Raises:
            PangeaAPIException: If an API error happens.

        Examples:
            exp_encrypted_resp = await vault.export(
                id=id,
                asymmetric_public_key=rsa_pub_key_pem,
                asymmetric_algorithm=ExportEncryptionAlgorithm.RSA4096_OAEP_SHA512,
            )
        """

        return await self.request.post(
            "v2/export",
            ExportResult,
            data=ExportRequest(
                id=item_id,
                version=version,
                kem_password=kem_password,
                asymmetric_public_key=asymmetric_public_key,
                asymmetric_algorithm=asymmetric_algorithm,
            ),
        )

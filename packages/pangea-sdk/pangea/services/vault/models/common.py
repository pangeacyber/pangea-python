# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from __future__ import annotations

import enum
from typing import Dict, Generic, List, Literal, Mapping, NewType, Optional, TypeVar, Union

from pangea.response import APIRequestModel, PangeaDateTime, PangeaResponseResult

# EncodedPublicKey is a PEM public key, with no further encoding (i.e. no base64)
# It may be used for example in openssh with no further processing
EncodedPublicKey = NewType("EncodedPublicKey", str)

# EncodedPrivateKey is a PEM private key, with no further encoding (i.e. no base64).
# It may be used for example in openssh with no further processing
EncodedPrivateKey = NewType("EncodedPrivateKey", str)

# EncodedSymmetricKey is a base64 encoded key
EncodedSymmetricKey = NewType("EncodedSymmetricKey", str)


Metadata = NewType("Metadata", Dict[str, str])
Tags = NewType("Tags", List[str])


class ItemOrder(str, enum.Enum):
    ASC = "asc"
    DESC = "desc"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class ItemOrderBy(str, enum.Enum):
    TYPE = "type"
    CREATED_AT = "created_at"
    DESTROYED_AT = "destroyed_at"
    IDENTITY = "identity"
    PURPOSE = "purpose"
    EXPIRATION = "expiration"
    LAST_ROTATED = "last_rotated"
    NEXT_ROTATION = "next_rotation"
    NAME = "name"
    FOLDER = "folder"
    VERSION = "version"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class ItemType(str, enum.Enum):
    ASYMMETRIC_KEY = "asymmetric_key"
    SYMMETRIC_KEY = "symmetric_key"
    SECRET = "secret"
    PANGEA_TOKEN = "pangea_token"
    PANGEA_CLIENT_SECRET = "pangea_client_secret"
    FOLDER = "folder"
    CERTIFICATE = "certificate"
    CERTIFICATE_AUTHORITY = "ca"
    CERTIFICATE_REVOCATION_LIST = "crl"


class ItemVersionState(str, enum.Enum):
    ACTIVE = "active"
    DEACTIVATED = "deactivated"
    SUSPENDED = "suspended"
    COMPROMISED = "compromised"
    DESTROYED = "destroyed"
    INHERITED = "inherited"


class RotationState(str, enum.Enum):
    DEACTIVATED = "deactivated"
    DESTROYED = "destroyed"


class RequestRotationState(str, enum.Enum):
    DEACTIVATED = "deactivated"
    DESTROYED = "destroyed"
    INHERITED = "inherited"


class RequestManualRotationState(str, enum.Enum):
    DEACTIVATED = "deactivated"
    SUSPENDED = "suspended"
    DESTROYED = "destroyed"
    INHERITED = "inherited"


class ItemState(str, enum.Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"

    value: str


class ExportEncryptionType(str, enum.Enum):
    NONE = "none"
    ASYMMETRIC = "asymmetric"
    KEM = "kem"


class ExportEncryptionAlgorithm(str, enum.Enum):
    """Algorithm of an exported public key."""

    RSA4096_OAEP_SHA512 = "RSA-OAEP-4096-SHA512"
    """RSA 4096-bit key, OAEP padding, SHA512 digest."""

    RSA_NO_PADDING_4096_KEM = "RSA-NO-PADDING-4096-KEM"


class CommonStoreResult(PangeaResponseResult):
    id: str
    type: str
    version: int


class CommonGenerateResult(PangeaResponseResult):
    type: str
    version: int
    id: str


class GetRequest(APIRequestModel):
    id: str
    version: Union[Literal["all"], int, None] = None


class GetBulkRequest(APIRequestModel):
    filter: Mapping[str, str]
    """Filters to customize a search."""

    size: Optional[int] = None
    """Maximum number of items in the response."""

    order: Optional[ItemOrder] = None
    """Direction for ordering the results."""

    order_by: Optional[ItemOrderBy] = None
    """Property by which to order the results."""

    last: Optional[str] = None
    """
    Internal ID returned in the previous look up response. Used for pagination.
    """


class ItemVersion(PangeaResponseResult):
    version: int
    created_at: str
    state: ItemVersionState
    destroyed_at: Optional[str] = None


class ItemData(PangeaResponseResult):
    type: str
    id: Optional[str] = None
    item_state: Optional[str] = None
    current_version: Optional[ItemVersion] = None
    name: Optional[str] = None
    folder: Optional[str] = None
    metadata: Optional[Metadata] = None
    tags: Optional[Tags] = None
    rotation_frequency: Optional[str] = None
    rotation_state: Optional[str] = None
    last_rotated: Optional[str] = None
    next_rotation: Optional[str] = None
    expiration: Optional[str] = None
    created_at: Optional[str] = None
    algorithm: Optional[str] = None
    purpose: Optional[str] = None
    exportable: Optional[bool] = None
    """Whether the key is exportable or not."""


class InheritedSettings(PangeaResponseResult):
    rotation_frequency: Optional[str] = None
    rotation_state: Optional[str] = None
    rotation_grace_period: Optional[str] = None


class Key(PangeaResponseResult):
    id: str
    type: ItemType
    item_state: Optional[ItemState] = None
    enabled: bool
    current_version: Optional[ItemVersion] = None
    name: str
    folder: str
    metadata: Optional[Metadata] = None
    tags: Optional[Tags] = None
    rotation_frequency: str
    rotation_state: RotationState
    last_rotated: Optional[str] = None
    next_rotation: str
    disabled_at: Optional[str] = None
    created_at: str
    algorithm: str
    purpose: str
    encrypting_item_id: Optional[str] = None
    inherited_settings: InheritedSettings
    exportable: bool
    """Whether the key is exportable or not."""


class SecretVersion(ItemVersion):
    secret: Optional[str] = None


class Secret(PangeaResponseResult):
    id: str
    type: Literal[ItemType.SECRET] = ItemType.SECRET
    enabled: bool
    name: str
    folder: str
    metadata: Optional[Metadata] = None
    tags: Optional[Tags] = None
    expiration: Optional[str] = None
    created_at: str
    encrypting_item_id: Optional[str] = None
    item_versions: List[SecretVersion]


class ClientSecret(PangeaResponseResult):
    id: str
    type: Literal[ItemType.PANGEA_CLIENT_SECRET] = ItemType.PANGEA_CLIENT_SECRET
    enabled: bool
    name: str
    folder: str
    metadata: Metadata
    tags: Tags
    expiration: str
    created_at: str
    encrypting_item_id: str
    rotation_frequency: str
    rotation_state: RotationState
    rotation_grace_period: str
    inherited_settings: InheritedSettings
    item_versions: List[SecretVersion]


class Folder(PangeaResponseResult):
    id: str
    type: Literal[ItemType.FOLDER] = ItemType.FOLDER
    name: str
    folder: str
    metadata: Metadata
    tags: Tags
    created_at: str
    inherited_settings: InheritedSettings


class ListItemData(PangeaResponseResult):
    id: str
    type: ItemType
    name: str
    folder: str
    created_at: str
    tags: Optional[Tags] = None
    metadata: Optional[Metadata] = None
    last_rotated: Optional[str] = None
    next_rotation: Optional[str] = None
    disabled_at: Optional[str] = None
    rotation_frequency: Optional[str] = None
    rotation_state: Optional[RotationState] = None
    algorithm: Optional[str] = None
    purpose: Optional[str] = None
    inherited_settings: Optional[InheritedSettings] = None
    compromised_versions: Optional[List[ItemVersion]] = None


class ListResult(PangeaResponseResult):
    items: List[ListItemData]

    last: Optional[str] = None
    """Internal ID returned in the previous look up response. Used for pagination."""


class ListRequest(APIRequestModel):
    filter: Optional[Mapping[str, str]] = None
    size: Optional[int] = None
    order: Optional[ItemOrder] = None
    order_by: Optional[ItemOrderBy] = None
    last: Optional[str] = None


class CommonRotateRequest(APIRequestModel):
    id: str
    rotation_state: RequestManualRotationState = RequestManualRotationState.DEACTIVATED


class CommonRotateResult(PangeaResponseResult):
    id: str
    version: int
    type: str


class KeyRotateResult(CommonRotateResult):
    public_key: Optional[EncodedPublicKey] = None
    algorithm: str
    purpose: str


class DeleteRequest(APIRequestModel):
    id: str
    recursive: bool = False


class DeleteResult(PangeaResponseResult):
    id: str
    """The ID of the item."""


class UpdateRequest(APIRequestModel):
    id: str
    name: Optional[str] = None
    folder: Optional[str] = None
    metadata: Optional[Metadata] = None
    tags: Optional[Tags] = None
    disabled_at: Optional[str] = None
    enabled: Optional[bool] = None
    rotation_frequency: Optional[str] = None
    rotation_state: RequestRotationState = RequestRotationState.INHERITED
    rotation_grace_period: Optional[str] = None


class UpdateResult(PangeaResponseResult):
    id: str


class JWKGetRequest(APIRequestModel):
    id: str
    version: Optional[str] = None


class JWKHeader(PangeaResponseResult):
    alg: str
    kid: Optional[str] = None
    kty: str
    use: Optional[str] = None


class JWK(JWKHeader):
    # Generic JWK
    pass


class JWKec(JWKHeader):
    # Elliptic curve JWK
    crv: str
    d: Optional[str] = None
    x: str
    y: str


class JWKrsa(JWKHeader):
    # RSA JWK
    n: str
    e: str
    d: Optional[str] = None


class JWKGetResult(PangeaResponseResult):
    keys: List[Union[JWKec, JWKrsa, JWK]]


class JWTVerifyRequest(APIRequestModel):
    jws: str


class JWTVerifyResult(PangeaResponseResult):
    valid_signature: bool
    """Indicates if messages have been verified."""


class JWTSignRequest(APIRequestModel):
    id: str
    payload: str


class JWTSignResult(PangeaResponseResult):
    jws: str
    """The signed JSON Web Token (JWS)."""


class StateChangeRequest(APIRequestModel):
    id: str
    state: ItemVersionState
    version: Optional[int] = None
    destroy_period: Optional[str] = None


class StateChangeResult(PangeaResponseResult):
    id: str
    version: int
    state: str
    destroy_at: Optional[str] = None


class FolderCreateRequest(APIRequestModel):
    name: str
    folder: str
    metadata: Optional[Metadata] = None
    tags: Optional[Tags] = None
    rotation_frequency: Optional[str] = None
    rotation_state: Optional[RequestRotationState] = None
    rotation_grace_period: Optional[str] = None
    disabled_at: Optional[PangeaDateTime] = None


class FolderCreateResult(PangeaResponseResult):
    id: str
    """The ID of the item."""

    type: str
    """The type of the folder."""

    name: str
    """The name of this item."""

    folder: str
    """The folder where this item is stored."""

    metadata: Optional[Metadata] = None
    """User-provided metadata."""

    tags: Optional[Tags] = None
    """A list of user-defined tags."""

    created_at: str
    """Timestamp indicating when the item was created."""

    inherited_settings: InheritedSettings
    """
    For settings that inherit a value from a parent folder, the full path of the
    folder where the value is set.
    """


TDict = TypeVar("TDict", bound=Dict)
"""Generic dictionary."""


class EncryptStructuredRequest(APIRequestModel, Generic[TDict]):
    id: str
    """The item ID."""

    structured_data: TDict
    """Structured data for applying bulk operations."""

    filter: str
    """A filter expression for applying bulk operations to the data field."""

    version: Optional[int] = None
    """The item version. Defaults to the current version."""

    additional_data: Optional[str] = None
    """User provided authentication data."""


class EncryptStructuredResult(PangeaResponseResult, Generic[TDict]):
    id: str
    """The ID of the item."""

    version: int
    """The item version."""

    algorithm: str
    """The algorithm of the key."""

    structured_data: TDict
    """Encrypted structured data."""


class TransformAlphabet(str, enum.Enum):
    """Set of characters to use for format-preserving encryption (FPE)."""

    NUMERIC = "numeric"
    """Numeric (0-9)."""

    ALPHA_LOWER = "alphalower"
    """Lowercase alphabet (a-z)."""

    ALPHA_UPPER = "alphaupper"
    """Uppercase alphabet (A-Z)."""

    ALPHANUMERIC_LOWER = "alphanumericlower"
    """Lowercase alphabet with numbers (a-z, 0-9)."""

    ALPHANUMERIC_UPPER = "alphanumericupper"
    """Uppercase alphabet with numbers (A-Z, 0-9)."""

    ALPHANUMERIC = "alphanumeric"
    """Alphanumeric (a-z, A-Z, 0-9)."""


class EncryptTransformRequest(APIRequestModel):
    id: str
    """The item ID."""

    plain_text: str
    """A message to be encrypted."""

    alphabet: TransformAlphabet
    """Set of characters to use for format-preserving encryption (FPE)."""

    tweak: Optional[str] = None
    """
    User provided tweak string. If not provided, a random string will be
    generated and returned. The user must securely store the tweak source which
    will be needed to decrypt the data.
    """

    version: Optional[int] = None
    """The item version."""


class EncryptTransformResult(PangeaResponseResult):
    id: str
    """The item ID."""

    version: int
    """The item version."""

    algorithm: str
    """The algorithm of the key."""

    cipher_text: str
    """The encrypted message."""

    tweak: str
    """
    User provided tweak string. If not provided, a random string will be
    generated and returned. The user must securely store the tweak source which
    will be needed to decrypt the data.
    """

    alphabet: str
    """Set of characters to use for format-preserving encryption (FPE)."""


class DecryptTransformRequest(APIRequestModel):
    id: str
    """The item ID."""

    cipher_text: str
    """A message encrypted by Vault."""

    tweak: str
    """
    User provided tweak string. If not provided, a random string will be
    generated and returned. The user must securely store the tweak source which
    will be needed to decrypt the data.
    """

    alphabet: TransformAlphabet
    """Set of characters to use for format-preserving encryption (FPE)."""

    version: Optional[int] = None
    """The item version."""


class DecryptTransformResult(PangeaResponseResult):
    id: str
    """The item ID."""

    version: int
    """The item version."""

    algorithm: str
    """The algorithm of the key."""

    plain_text: str
    """Decrypted message."""


class ExportRequest(APIRequestModel):
    id: str
    """The ID of the item."""

    version: Optional[int] = None
    """The item version."""

    kem_password: Optional[str] = None
    """
    This is the password that will be used along with a salt to derive the
    symmetric key that is used to encrypt the exported key material.
    """

    asymmetric_public_key: Optional[str] = None
    """Public key in pem format used to encrypt exported key(s)."""

    asymmetric_algorithm: Optional[ExportEncryptionAlgorithm] = None
    """The algorithm of the public key."""


class ExportResult(PangeaResponseResult):
    id: str
    """The ID of the key."""

    type: ItemType
    """The type of the key."""

    version: int
    """The item version."""

    enabled: bool
    """True if the item is enabled."""

    algorithm: str
    """The algorithm of the key."""

    asymmetric_algorithm: Optional[ExportEncryptionAlgorithm] = None
    """The algorithm of the public key used to encrypt exported material."""

    symmetric_algorithm: Optional[str] = None

    encryption_type: ExportEncryptionType
    """
    Encryption format of the exported key(s). It could be `none` if returned in
    plain text, `asymmetric` if it is encrypted just with the public key sent in
    `encryption_public_key`, or `kem` if it was encrypted using KEM protocol.
    """

    kdf: Optional[str] = None
    """
    Key derivation function used to derivate the symmetric key when
    `encryption_type` is `kem`.
    """

    hash_algorithm: Optional[str] = None
    """
    Hash algorithm used to derivate the symmetric key when `encryption_type` is
    `kem`.
    """

    iteration_count: Optional[int] = None
    """
    Iteration count used to derivate the symmetric key when `encryption_type` is
    `kem`.
    """

    encrypted_salt: Optional[str] = None
    """
    Salt used to derivate the symmetric key when `encryption_type` is `kem`,
    encrypted with the public key provided in `asymmetric_key`.
    """

    public_key: Optional[str] = None
    """The public key (in PEM format)."""

    private_key: Optional[str] = None
    """The private key (in PEM format)."""

    key: Optional[str] = None
    """The key material."""


class PangeaTokenVersion(ItemVersion):
    token: Optional[str] = None
    """Pangea token value."""


class PangeaToken(PangeaResponseResult):
    id: str
    """ID of the token."""

    type: Literal[ItemType.PANGEA_TOKEN] = ItemType.PANGEA_TOKEN
    """Type of the Vault item."""

    item_versions: List[PangeaTokenVersion]

    metadata: Optional[Metadata] = None
    """Metadata provided by the user."""

    num_versions: int
    """Total number of versions of the item."""

    enabled: bool
    """`true` if the item is enabled."""

    name: str
    """Name of the item."""

    folder: str
    """Folder where the item is stored."""

    tags: Tags
    """List of user-defined tags."""

    last_rotated: Optional[str] = None
    """Timestamp of the last rotation."""

    next_rotation: Optional[str] = None
    """Timestamp of the next rotation if auto-rotation is enabled."""

    disabled_at: Optional[str] = None
    """Timestamp indicating when the item will be disabled."""

    created_at: str
    """Timestamp indicating when the item was created."""

    rotation_frequency: str
    """Time interval between item rotations."""

    rotation_state: RotationState
    """Target state for the previous version after rotation."""

    rotation_grace_period: str
    """Grace period for the previous version."""

    inherited_settings: InheritedSettings
    """Full paths of the parent folders from which settings inherit their values."""


class PangeaTokenRotateRequest(CommonRotateRequest):
    rotation_grace_period: Optional[str] = None


class ClientSecretRotateRequest(CommonRotateRequest):
    rotation_grace_period: Optional[str] = None

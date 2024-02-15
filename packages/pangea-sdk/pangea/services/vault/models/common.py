# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import datetime
import enum
from typing import Dict, Generic, List, NewType, Optional, TypeVar, Union

from pangea.response import APIRequestModel, PangeaResponseResult

# EncodedPublicKey is a PEM public key, with no further encoding (i.e. no base64)
# It may be used for example in openssh with no further processing
EncodedPublicKey = NewType("EncodedPublicKey", str)

# EncodedPrivateKey is a PEM private key, with no further encoding (i.e. no base64).
# It may be used for example in openssh with no further processing
EncodedPrivateKey = NewType("EncodedPrivateKey", str)

# EncodedSymmetricKey is a base64 encoded key
EncodedSymmetricKey = NewType("EncodedSymmetricKey", str)


class KeyPurpose(str, enum.Enum):
    SIGNING = "signing"
    ENCRYPTION = "encryption"
    JWT = "jwt"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class AsymmetricAlgorithm(str, enum.Enum):
    Ed25519 = "ED25519"
    RSA2048_PKCS1V15_SHA256 = "RSA-PKCS1V15-2048-SHA256"
    RSA2048_OAEP_SHA256 = "RSA-OAEP-2048-SHA256"
    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"
    ES256K = "ES256K"
    RSA2048_OAEP_SHA1 = "RSA-OAEP-2048-SHA1"
    RSA2048_OAEP_SHA512 = "RSA-OAEP-2048-SHA512"
    RSA3072_OAEP_SHA1 = "RSA-OAEP-3072-SHA1"
    RSA3072_OAEP_SHA256 = "RSA-OAEP-3072-SHA256"
    RSA3072_OAEP_SHA512 = "RSA-OAEP-3072-SHA512"
    RSA4096_OAEP_SHA1 = "RSA-OAEP-4096-SHA1"
    RSA4096_OAEP_SHA256 = "RSA-OAEP-4096-SHA256"
    RSA4096_OAEP_SHA512 = "RSA-OAEP-4096-SHA512"
    RSA2048_PSS_SHA256 = "RSA-PSS-2048-SHA256"
    RSA3072_PSS_SHA256 = "RSA-PSS-3072-SHA256"
    RSA4096_PSS_SHA256 = "RSA-PSS-4096-SHA256"
    RSA4096_PSS_SHA512 = "RSA-PSS-4096-SHA512"
    RSA = "RSA-PKCS1V15-2048-SHA256"  # deprecated, use RSA2048_PKCS1V15_SHA256 instead
    Ed25519_DILITHIUM2_BETA = "ED25519-DILITHIUM2-BETA"
    Ed448_DILITHIUM3_BETA = "ED448-DILITHIUM3-BETA"
    SPHINCSPLUS_128F_SHAKE256_SIMPLE_BETA = "SPHINCSPLUS-128F-SHAKE256-SIMPLE-BETA"
    SPHINCSPLUS_128F_SHAKE256_ROBUST_BETA = "SPHINCSPLUS-128F-SHAKE256-ROBUST-BETA"
    SPHINCSPLUS_192F_SHAKE256_SIMPLE_BETA = "SPHINCSPLUS-192F-SHAKE256-SIMPLE-BETA"
    SPHINCSPLUS_192F_SHAKE256_ROBUST_BETA = "SPHINCSPLUS-192F-SHAKE256-ROBUST-BETA"
    SPHINCSPLUS_256F_SHAKE256_SIMPLE_BETA = "SPHINCSPLUS-256F-SHAKE256-SIMPLE-BETA"
    SPHINCSPLUS_256F_SHAKE256_ROBUST_BETA = "SPHINCSPLUS-256F-SHAKE256-ROBUST-BETA"
    SPHINCSPLUS_128F_SHA256_SIMPLE_BETA = "SPHINCSPLUS-128F-SHA256-SIMPLE-BETA"
    SPHINCSPLUS_128F_SHA256_ROBUST_BETA = "SPHINCSPLUS-128F-SHA256-ROBUST-BETA"
    SPHINCSPLUS_192F_SHA256_SIMPLE_BETA = "SPHINCSPLUS-192F-SHA256-SIMPLE-BETA"
    SPHINCSPLUS_192F_SHA256_ROBUST_BETA = "SPHINCSPLUS-192F-SHA256-ROBUST-BETA"
    SPHINCSPLUS_256F_SHA256_SIMPLE_BETA = "SPHINCSPLUS-256F-SHA256-SIMPLE-BETA"
    SPHINCSPLUS_256F_SHA256_ROBUST_BETA = "SPHINCSPLUS-256F-SHA256-ROBUST-BETA"
    FALCON_1024_BETA = "FALCON-1024-BETA"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class SymmetricAlgorithm(str, enum.Enum):
    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"
    AES128_CFB = "AES-CFB-128"
    AES256_CFB = "AES-CFB-256"
    AES256_GCM = "AES-GCM-256"
    AES128_CBC = "AES-CBC-128"
    AES256_CBC = "AES-CBC-256"
    AES = "AES-CFB-128"  # deprecated, use AES128_CFB instead

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


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

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class ItemVersionState(str, enum.Enum):
    ACTIVE = "active"
    DEACTIVATED = "deactivated"
    SUSPENDED = "suspended"
    COMPROMISED = "compromised"
    DESTROYED = "destroyed"
    INHERITED = "inherited"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class ItemState(str, enum.Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class CommonStoreRequest(APIRequestModel):
    type: ItemType
    name: str
    folder: Optional[str] = None
    metadata: Optional[Metadata] = None
    tags: Optional[Tags] = None
    rotation_frequency: Optional[str] = None
    rotation_state: Optional[ItemVersionState] = None
    expiration: Optional[datetime.datetime] = None


class CommonStoreResult(PangeaResponseResult):
    id: str
    type: str
    version: int


class CommonGenerateRequest(APIRequestModel):
    type: ItemType
    name: str
    folder: Optional[str] = None
    metadata: Optional[Metadata] = None
    tags: Optional[Tags] = None
    rotation_frequency: Optional[str] = None
    rotation_state: Optional[ItemVersionState] = None
    expiration: Optional[datetime.datetime] = None


class CommonGenerateResult(PangeaResponseResult):
    type: str
    version: int
    id: str


class GetRequest(APIRequestModel):
    id: str
    version: Optional[Union[str, int]] = None
    verbose: Optional[bool] = None
    version_state: Optional[ItemVersionState] = None


class ItemVersionData(PangeaResponseResult):
    version: int
    state: str
    created_at: str
    destroy_at: Optional[str] = None
    public_key: Optional[EncodedPublicKey] = None
    secret: Optional[str] = None


class ItemData(PangeaResponseResult):
    type: str
    id: Optional[str] = None
    item_state: Optional[str] = None
    current_version: Optional[ItemVersionData] = None
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


class InheritedSettings(PangeaResponseResult):
    rotation_frequency: Optional[str] = None
    rotation_state: Optional[str] = None
    rotation_grace_period: Optional[str] = None


class GetResult(ItemData):
    versions: List[ItemVersionData] = []
    rotation_grace_period: Optional[str] = None
    inherited_settings: Optional[InheritedSettings] = None


class ListItemData(ItemData):
    compromised_versions: Optional[List[ItemVersionData]] = None


class ListResult(PangeaResponseResult):
    items: List[ListItemData] = []
    count: int
    last: Optional[str]


class ListRequest(APIRequestModel):
    filter: Optional[Dict[str, str]] = None
    size: Optional[int] = None
    order: Optional[ItemOrder] = None
    order_by: Optional[ItemOrderBy] = None
    last: Optional[str] = None


class CommonRotateRequest(APIRequestModel):
    id: str
    rotation_state: Optional[ItemVersionState] = None


class CommonRotateResult(PangeaResponseResult):
    id: str
    version: int
    type: str


class KeyRotateRequest(CommonRotateRequest):
    key: Optional[str] = None
    public_key: Optional[EncodedPublicKey] = None
    private_key: Optional[EncodedPrivateKey] = None


class KeyRotateResult(CommonRotateResult):
    public_key: Optional[EncodedPublicKey] = None
    algorithm: str
    purpose: str


class DeleteRequest(APIRequestModel):
    id: str


class DeleteResult(PangeaResponseResult):
    id: str


class UpdateRequest(APIRequestModel):
    id: str
    name: Optional[str] = None
    folder: Optional[str] = None
    metadata: Optional[Metadata] = None
    tags: Optional[Tags] = None
    rotation_frequency: Optional[str] = None
    rotation_state: Optional[ItemVersionState] = None
    rotation_grace_period: Optional[str] = None
    expiration: Optional[datetime.datetime] = None
    item_state: Optional[ItemState] = None


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


class JWTSignRequest(APIRequestModel):
    id: str
    payload: str


class JWTSignResult(PangeaResponseResult):
    jws: str


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
    rotation_state: Optional[ItemVersionState] = None
    rotation_grace_period: Optional[str] = None


class FolderCreateResult(PangeaResponseResult):
    id: str


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

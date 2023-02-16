# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import datetime
import enum
from typing import Any, Dict, List, NewType, Optional, Union

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
    Ed25519 = "ed25519"
    RSA = "rsa"
    ES256 = "es256"
    ES384 = "es384"
    ES512 = "es512"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class SymmetricAlgorithm(str, enum.Enum):
    AES = "aes"
    HS256 = "hs256"
    HS384 = "hs384"
    HS512 = "hs512"

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
    REVOKED_AT = "revoked_at"
    IDENTITY = "identity"
    MANAGED = "managed"
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


class CommonStoreRequest(APIRequestModel):
    type: ItemType
    name: Optional[str] = None
    folder: Optional[str] = None
    metadata: Optional[Metadata] = None
    tags: Optional[Tags] = None
    auto_rotate: Optional[bool] = None
    rotation_policy: Optional[str] = None
    expiration: Optional[datetime.datetime] = None


class CommonStoreResult(PangeaResponseResult):
    id: str
    type: str
    version: int


class CommonGenerateRequest(APIRequestModel):
    type: ItemType
    name: Optional[str] = None
    folder: Optional[str] = None
    metadata: Optional[Metadata] = None
    tags: Optional[Tags] = None
    auto_rotate: Optional[bool] = None
    rotation_policy: Optional[str] = None
    store: Optional[bool] = None
    expiration: Optional[datetime.datetime] = None
    managed: Optional[bool] = None


class CommonGenerateResult(PangeaResponseResult):
    type: str
    version: Optional[int] = None
    id: Optional[str] = None


class GetRequest(APIRequestModel):
    id: str
    version: Optional[int] = None
    verbose: Optional[bool] = None


class CommonGetResult(PangeaResponseResult):
    type: str
    id: str
    version: int
    name: Optional[str] = None
    folder: Optional[str] = None
    metadata: Optional[Metadata] = None
    tags: Optional[Tags] = None
    auto_rotate: Optional[bool] = None
    rotation_policy: Optional[str] = None
    last_rotated: Optional[str] = None  # TODO: should be time
    next_rotation: Optional[str] = None  # TODO: should be time
    expiration: Optional[str] = None  # TODO: should be time
    created_at: Optional[str] = None  # TODO: should be time
    revoked_at: Optional[str] = None  # TODO: should be time
    retain_previous_version: Optional[bool] = None


class ListItemData(APIRequestModel):
    id: str
    type: str
    managed: bool
    last_rotated: Optional[str] = None  # TODO: should be time
    next_rotation: Optional[str] = None  # TODO: should be time
    expiration: Optional[str] = None  # TODO: should be time
    rotation_policy: Optional[str] = None
    identity: str
    version: int
    name: Optional[str] = None
    folder: Optional[str] = None
    metadata: Optional[Metadata] = None
    tags: Optional[Tags] = None
    created_at: str  # TODO: should be time
    revoked_at: Optional[str] = None  # TODO: should be time


class ListResult(PangeaResponseResult):
    items: List[ListItemData] = []
    count: int
    last: Optional[str]


class ListRequest(APIRequestModel):
    filter: Optional[Dict[str, str]] = None
    restrictions: Optional[Dict[str, List[str]]] = None
    size: Optional[int] = None
    order: Optional[ItemOrder] = None
    order_by: Optional[ItemOrderBy] = None
    last: Optional[str] = None


class GetResult(CommonGetResult):
    public_key: Optional[EncodedPublicKey] = None
    private_key: Optional[EncodedPrivateKey] = None
    secret: Optional[str] = None
    key: Optional[EncodedSymmetricKey]
    algorithm: Optional[Union[AsymmetricAlgorithm, SymmetricAlgorithm]] = None
    purpose: Optional[KeyPurpose] = None
    managed: Optional[bool] = None


class CommonRotateRequest(APIRequestModel):
    id: str


class CommonRotateResult(PangeaResponseResult):
    id: str
    version: int
    type: str


class KeyRotateRequest(CommonRotateRequest):
    key: Optional[str]
    public_key: Optional[EncodedPublicKey] = None
    private_key: Optional[EncodedPrivateKey] = None


class KeyRotateResult(CommonRotateResult):
    public_key: Optional[EncodedPublicKey] = None
    private_key: Optional[EncodedPrivateKey] = None
    key: Optional[EncodedSymmetricKey] = None
    algorithm: Union[SymmetricAlgorithm, AsymmetricAlgorithm]


class RevokeRequest(APIRequestModel):
    id: str


class RevokeResult(PangeaResponseResult):
    id: str


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
    auto_rotate: Optional[bool] = None
    rotation_policy: Optional[str] = None
    retain_previous_version: Optional[bool] = None
    expiration: Optional[datetime.datetime] = None


class UpdateResult(APIRequestModel):
    id: str


class JWTGetRequest(APIRequestModel):
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
    # Eliptyc curve JWK
    crv: str
    d: Optional[str] = None
    x: str
    y: str


class JWKrsa(JWKHeader):
    # RSA JWK
    n: str
    e: str
    d: Optional[str] = None


class JWKSet(PangeaResponseResult):
    keys: List[Union[JWKec, JWKrsa, JWK]]


class JWTGetResult(PangeaResponseResult):
    jwk: JWKSet


class JWTVerifyRequest(APIRequestModel):
    jws: str


class JWTVerifyResult(PangeaResponseResult):
    valid_signature: bool


class JWTSignRequest(APIRequestModel):
    id: str
    payload: str


class JWTSignResult(PangeaResponseResult):
    jws: str

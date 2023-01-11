# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import datetime
import enum
from typing import Dict, List, NewType, Optional

from pangea.response import APIRequestModel, PangeaResponseResult

# EncodedPublicKey is a PEM public key, with no further encoding (i.e. no base64)
# It may be used for example in openssh with no further processing
EncodedPublicKey = NewType("EncodedPublicKey", str)

# EncodedPrivateKey is a PEM private key, with no further encoding (i.e. no base64).
# It may be used for example in openssh with no further processing
EncodedPrivateKey = NewType("EncodedPrivateKey", str)

# EncodedSymmetricKey is a base64 encoded key
EncodedSymmetricKey = NewType("EncodedSymmetricKey", str)


class KeyPairPurpose(str, enum.Enum):
    SIGNING = "signing"
    ENCRYPTION = "encryption"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class KeyPairAlgorithm(str, enum.Enum):
    Ed25519 = "ed25519"
    RSA = "rsa"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class KeyAlgorithm(str, enum.Enum):
    AES = "aes"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


Metadata = NewType("Metadata", Dict[str, str])
Tags = NewType("Tags", List[str])


class ItemType(str, enum.Enum):
    ASYMMETRIC_KEY = "asymmetric_key"
    SYMMETRIC_KEY = "symmetric_key"
    SECRET = "secret"
    MASTER_KEY = "master_key"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class StoreCommonRequest(APIRequestModel):
    type: ItemType
    name: Optional[str] = None
    folder: Optional[str] = None
    metadata: Optional[Metadata] = None
    tags: Optional[Tags] = None
    auto_rotate: Optional[bool] = None
    rotation_policy: Optional[str] = None
    retain_previous_version: Optional[bool] = None
    expiration: Optional[datetime.datetime] = None
    managed: Optional[bool] = None


class StoreCommonResult(PangeaResponseResult):
    id: str
    type: str
    version: int


class CreateCommonRequest(APIRequestModel):
    type: ItemType
    name: Optional[str] = None
    folder: Optional[str] = None
    metadata: Optional[Metadata] = None
    tags: Optional[Tags] = None
    auto_rotate: Optional[bool] = None
    rotation_policy: Optional[str] = None
    retain_previous_version: Optional[bool] = None
    store: Optional[bool] = None
    expiration: Optional[datetime.datetime] = None
    managed: Optional[bool] = None


class CreateCommonResult(PangeaResponseResult):
    type: str
    version: Optional[int] = None
    id: Optional[str] = None


class GetCommonRequest(APIRequestModel):
    id: str
    version: Optional[int] = None
    verbose: Optional[bool] = None


class GetCommonResult(PangeaResponseResult):
    id: str
    type: str
    version: int
    name: Optional[str] = None
    folder: Optional[str] = None
    metadata: Optional[Metadata] = None
    tags: Optional[Tags] = None
    rotation_policy: Optional[str] = None
    auto_rotate: Optional[bool] = None
    last_rotated: Optional[str] = None  # TODO: should be time
    next_rotation: Optional[str] = None  # TODO: should be time
    retaion_previous_version: Optional[bool] = None
    expiration: Optional[str] = None  # TODO: should be time
    created_at: Optional[str] = None  # TODO: should be time
    revoked_at: Optional[str] = None  # TODO: should be time


class ListItemData(APIRequestModel):
    type: str
    name: Optional[str] = None
    folder: Optional[str] = None
    id: str
    created_at: str  # TODO: should be time
    revoked_at: Optional[str] = None  # TODO: should be time
    tags: Optional[Tags] = None
    metadata: Optional[Metadata] = None
    managed: Optional[bool] = None
    next_rotation: Optional[str] = None  # TODO: should be time
    expiration: Optional[str] = None  # TODO: should be time
    rotation_policy: Optional[str] = None
    identity: str
    version: int


class ListFolderData(APIRequestModel):
    type: str
    name: Optional[str] = None
    folder: Optional[str] = None


class ListResult(PangeaResponseResult):
    items: List[ListItemData | ListFolderData] = []
    count: int
    last: Optional[str]


class ListRequest(APIRequestModel):
    filter: Optional[Dict[str, str]] = None
    restrictions: Optional[Dict[str, List[str]]] = None
    last: Optional[str] = None
    size: Optional[int] = None
    order: Optional[str] = None
    order_by: Optional[str] = None


class GetGenericResult(GetCommonResult):
    public_key: Optional[EncodedPublicKey] = None
    private_key: Optional[EncodedPrivateKey] = None
    algorithm: Optional[KeyPairAlgorithm | KeyAlgorithm] = None
    purpose: Optional[KeyPairPurpose] = None
    key: Optional[EncodedSymmetricKey]
    managed: Optional[bool] = None
    secret: Optional[str] = None


class RotateCommonRequest(APIRequestModel):
    id: str


class RotateCommonResult(PangeaResponseResult):
    id: str
    version: int
    type: str


class RotateGenericKeyResult(RotateCommonResult):
    public_key: Optional[EncodedPublicKey] = None
    private_key: Optional[EncodedPrivateKey] = None
    key: Optional[EncodedSymmetricKey] = None


class RevokeRequest(APIRequestModel):
    id: str


class RevokeResult(PangeaResponseResult):
    # id: str
    pass


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
    expiration: Optional[datetime.datetime] = None


class UpdateResult(APIRequestModel):
    id: str

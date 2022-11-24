# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import datetime
import enum
import json
from typing import Dict, List, NewType, Optional, Union

from pangea.response import PangeaResponseResult
from pangea.utils import format_datetime
from pydantic import BaseModel

# EncodedPublicKey is a PEM public key, with no further encoding (i.e. no base64)
# It may be used for example in openssh with no further processing
EncodedPublicKey = NewType("EncodedPublicKey", str)

# EncodedPrivateKey is a PEM private key, with no further encoding (i.e. no base64).
# It may be used for example in openssh with no further processing
EncodedPrivateKey = NewType("EncodedPrivateKey", str)


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


class BaseModelConfig(BaseModel):
    class Config:
        arbitrary_types_allowed = True
        extra = "allow"

    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return format_datetime(obj)
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


Medatada = NewType("Metadata", Dict[str, str])
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


class StoreCommonRequest(BaseModelConfig):
    type: ItemType
    name: Optional[str] = None
    type: ItemType
    folder: Optional[str] = None
    metadata: Optional[Medatada] = None
    rotation_policy: Optional[str] = None
    tags: Optional[Tags] = None
    expiration: Optional[datetime.datetime] = None
    auto_rotate: Optional[bool] = None
    retain_previous_version: Optional[bool] = None


class StoreCommonResult(PangeaResponseResult):
    id: str
    type: str
    version: int


class CreateCommonRequest(BaseModelConfig):
    name: Optional[str] = None
    folder: Optional[str] = None
    metadata: Optional[Medatada] = None
    rotation_policy: Optional[str] = None
    expiration: Optional[datetime.datetime]  # TODO: should be datetime
    tags: Optional[Tags] = None
    auto_rotate: Optional[bool] = None
    retain_previous_version: Optional[bool] = None
    store: Optional[bool] = None


class CreateCommonResult(PangeaResponseResult):
    id: Optional[str] = None
    version: int


class RetrieveRequest(BaseModelConfig):
    id: str
    version: Optional[int] = None
    verbose: Optional[bool] = None


class RetrieveCommonResult(PangeaResponseResult):
    id: str
    type: str
    version: int
    name: Optional[str] = None
    folder: Optional[str] = None
    metadata: Optional[Medatada] = None
    tags: Optional[Tags] = None
    rotation_policy: Optional[str] = None
    auto_rotate: Optional[bool] = None
    last_rotated: Optional[str] = None  # TODO: should be time
    next_rotation: Optional[str] = None  # TODO: should be time
    retaion_previous_version: Optional[bool] = None
    expiration: Optional[str] = None  # TODO: should be time
    created_at: Optional[str] = None  # TODO: should be time
    revoked_at: Optional[str] = None  # TODO: should be time


class ListData(BaseModelConfig):
    id: str
    created_at: str  # TODO: should be time
    name: Optional[str] = None
    folder: Optional[str] = None
    tags: Optional[Tags] = None
    metadata: Optional[Medatada] = None
    revoked_at: Optional[str] = None  # TODO: should be time


class ListResult(PangeaResponseResult):
    items: List[ListData] = []
    last: str


class ListRequest(BaseModelConfig):
    filter: Optional[Dict[str, List[str]]] = None
    restrictions: Optional[Dict[str, List[str]]] = None
    last: Optional[str] = None
    size: Optional[int] = None
    order: Optional[str] = None
    order_by: Optional[str] = None


class RetrieveGenericResult(RetrieveCommonResult):
    public_key: Optional[EncodedPublicKey] = None
    private_key: Optional[EncodedPrivateKey] = None
    algorithm: Optional[KeyPairAlgorithm | KeyAlgorithm] = None
    purpose: Optional[KeyPairPurpose] = None
    key: Optional[str]
    managed: Optional[bool] = None
    secret: Optional[str] = None


class RotateCommonRequest(BaseModelConfig):
    id: str


class RotateCommonResult(PangeaResponseResult):
    id: str
    version: int


class RotateGenericKeyResult(RotateCommonResult):
    public_key: Optional[EncodedPublicKey] = None
    private_key: Optional[EncodedPrivateKey] = None
    key: Optional[str] = None


class RevokeRequest(BaseModelConfig):
    id: str


class RevokeResult(PangeaResponseResult):
    # id: str
    pass

# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from __future__ import annotations

from enum import Enum
from typing import List, Optional, Union

from typing_extensions import Literal

from pangea.response import APIRequestModel, PangeaResponseResult
from pangea.services.vault.models.common import CommonGenerateResult, CommonStoreResult, ItemType, ItemVersion, Key


class SymmetricStoreResult(CommonStoreResult):
    algorithm: str
    purpose: str


class SymmetricGenerateResult(CommonGenerateResult):
    algorithm: str
    purpose: str


class EncryptRequest(APIRequestModel):
    id: str
    plain_text: str
    version: Optional[int] = None
    additional_data: Optional[str] = None


class EncryptResult(PangeaResponseResult):
    id: str
    """The ID of the item."""

    version: int
    """The item version."""

    algorithm: str
    """The algorithm of the key."""

    cipher_text: str
    """The encrypted message (Base64 encoded)."""


class DecryptRequest(APIRequestModel):
    id: str
    cipher_text: str
    version: Optional[int] = None
    additional_data: Optional[str] = None


class DecryptResult(PangeaResponseResult):
    id: str
    """The ID of the item."""

    version: int
    """The item version."""

    algorithm: str
    """The algorithm of the key."""

    plain_text: str
    """The decrypted message."""


class SymmetricKeyPurpose(str, Enum):
    """The purpose of a symmetric key."""

    ENCRYPTION = "encryption"
    JWT = "jwt"
    FPE = "fpe"
    """Format-preserving encryption."""


class SymmetricKeyEncryptionAlgorithm(str, Enum):
    AES_CFB_128 = "AES-CFB-128"
    AES_CFB_256 = "AES-CFB-256"
    AES_GCM_256 = "AES-GCM-256"
    AES_CBC_128 = "AES-CBC-128"
    AES_CBC_256 = "AES-CBC-256"


class SymmetricKeyJwtAlgorithm(str, Enum):
    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"


class SymmetricKeyFpeAlgorithm(str, Enum):
    """The algorithm of the key for purpose=`fpe` (Format Preserving Encryption)."""

    AES_FF3_1_128_BETA = "AES-FF3-1-128-BETA"
    """128-bit encryption using the FF3-1 algorithm."""

    AES_FF3_1_256_BETA = "AES-FF3-1-256-BETA"
    """256-bit encryption using the FF3-1 algorithm."""


SymmetricKeyAlgorithm = Union[SymmetricKeyEncryptionAlgorithm, SymmetricKeyJwtAlgorithm, SymmetricKeyFpeAlgorithm]
"""The algorithm of a symmetric key."""


class SymmetricKeyVersion(ItemVersion):
    pass


class SymmetricKey(Key):
    type: Literal[ItemType.SYMMETRIC_KEY] = ItemType.SYMMETRIC_KEY
    item_versions: List[SymmetricKeyVersion]

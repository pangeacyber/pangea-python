# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from __future__ import annotations

from enum import Enum
from typing import List, Optional, Union

from typing_extensions import Literal

from pangea.response import APIRequestModel, PangeaResponseResult
from pangea.services.vault.models.common import (
    CommonGenerateResult,
    CommonStoreResult,
    EncodedPublicKey,
    ItemType,
    ItemVersion,
    Key,
)


class AsymmetricGenerateResult(CommonGenerateResult):
    algorithm: str
    purpose: str
    public_key: EncodedPublicKey


class AsymmetricStoreResult(CommonStoreResult):
    algorithm: str
    purpose: str
    public_key: EncodedPublicKey


class SignRequest(APIRequestModel):
    id: str
    message: str
    version: Optional[int] = None


class SignResult(PangeaResponseResult):
    id: str
    """The ID of the item."""

    version: int
    """The item version."""

    algorithm: str
    """The algorithm of the key."""

    signature: str
    """The signature of the message."""

    public_key: Optional[EncodedPublicKey] = None
    """The public key (in PEM format)."""


class VerifyRequest(APIRequestModel):
    id: str
    message: str
    signature: str
    version: Optional[int] = None


class VerifyResult(PangeaResponseResult):
    id: str
    """The ID of the item."""

    version: int
    """The item version."""

    algorithm: str
    """The algorithm of the key."""

    valid_signature: bool
    """Indicates if messages have been verified."""


class AsymmetricKeyPurpose(str, Enum):
    """The purpose of an asymmetric key."""

    SIGNING = "signing"
    ENCRYPTION = "encryption"
    JWT = "jwt"
    PKI = "pki"


class AsymmetricKeySigningAlgorithm(str, Enum):
    """The algorithm of the key for purpose=`signing`."""

    ED25519 = "ED25519"
    RSA_PKCS1V15_2048_SHA256 = "RSA-PKCS1V15-2048-SHA256"
    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"
    ES256K = "ES256K"
    RSA_PSS_2048_SHA256 = "RSA-PSS-2048-SHA256"
    RSA_PSS_3072_SHA256 = "RSA-PSS-3072-SHA256"
    RSA_PSS_4096_SHA256 = "RSA-PSS-4096-SHA256"
    RSA_PSS_4096_SHA512 = "RSA-PSS-4096-SHA512"
    ED25519_DILITHIUM2_BETA = "ED25519-DILITHIUM2-BETA"
    ED448_DILITHIUM3_BETA = "ED448-DILITHIUM3-BETA"
    SPHINCSPLUS_128F_SHAKE256_SIMPLE_BETA = "SPHINCSPLUS-128F-SHAKE256-SIMPLE-BETA"
    SPHINCSPLUS_128F_SHAKE256_ROBUST_BETA = "SPHINCSPLUS-128F-SHAKE256-ROBUST-BETA"
    SPHINCSPLUS_128F_SHA256_SIMPLE_BETA = "SPHINCSPLUS-128F-SHA256-SIMPLE-BETA"
    SPHINCSPLUS_128F_SHA256_ROBUST_BETA = "SPHINCSPLUS-128F-SHA256-ROBUST-BETA"
    SPHINCSPLUS_192F_SHAKE256_SIMPLE_BETA = "SPHINCSPLUS-192F-SHAKE256-SIMPLE-BETA"
    SPHINCSPLUS_192F_SHAKE256_ROBUST_BETA = "SPHINCSPLUS-192F-SHAKE256-ROBUST-BETA"
    SPHINCSPLUS_192F_SHA256_SIMPLE_BETA = "SPHINCSPLUS-192F-SHA256-SIMPLE-BETA"
    SPHINCSPLUS_192F_SHA256_ROBUST_BETA = "SPHINCSPLUS-192F-SHA256-ROBUST-BETA"
    SPHINCSPLUS_256F_SHAKE256_SIMPLE_BETA = "SPHINCSPLUS-256F-SHAKE256-SIMPLE-BETA"
    SPHINCSPLUS_256F_SHAKE256_ROBUST_BETA = "SPHINCSPLUS-256F-SHAKE256-ROBUST-BETA"
    SPHINCSPLUS_256F_SHA256_SIMPLE_BETA = "SPHINCSPLUS-256F-SHA256-SIMPLE-BETA"
    SPHINCSPLUS_256F_SHA256_ROBUST_BETA = "SPHINCSPLUS-256F-SHA256-ROBUST-BETA"
    FALCON_1024_BETA = "FALCON-1024-BETA"


class AsymmetricKeyEncryptionAlgorithm(str, Enum):
    """The algorithm of the key for purpose=`encryption`."""

    RSA_OAEP_2048_SHA1 = "RSA-OAEP-2048-SHA1"
    RSA_OAEP_2048_SHA256 = "RSA-OAEP-2048-SHA256"
    RSA_OAEP_2048_SHA512 = "RSA-OAEP-2048-SHA512"
    RSA_OAEP_3072_SHA1 = "RSA-OAEP-3072-SHA1"
    RSA_OAEP_3072_SHA256 = "RSA-OAEP-3072-SHA256"
    RSA_OAEP_3072_SHA512 = "RSA-OAEP-3072-SHA512"
    RSA_OAEP_4096_SHA1 = "RSA-OAEP-4096-SHA1"
    RSA_OAEP_4096_SHA256 = "RSA-OAEP-4096-SHA256"
    RSA_OAEP_4096_SHA512 = "RSA-OAEP-4096-SHA512"


class AsymmetricKeyJwtAlgorithm(str, Enum):
    """The algorithm of the key for purpose=`jwt`."""

    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"


class AsymmetricKeyPkiAlgorithm(str, Enum):
    """The algorithm of the key for purpose=`pki`."""

    ED25519 = "ED25519"
    RSA_2048_SHA256 = "RSA-2048-SHA256"
    RSA_3072_SHA256 = "RSA-3072-SHA256"
    RSA_4096_SHA256 = "RSA-4096-SHA256"
    RSA_PSS_2048_SHA256 = "RSA-PSS-2048-SHA256"
    RSA_PSS_3072_SHA256 = "RSA-PSS-3072-SHA256"
    RSA_PSS_4096_SHA256 = "RSA-PSS-4096-SHA256"
    RSA_PSS_4096_SHA512 = "RSA-PSS-4096-SHA512"
    ECDSA_SHA256 = "ECDSA-SHA256"
    ECDSA_SHA384 = "ECDSA-SHA384"
    ECDSA_SHA512 = "ECDSA-SHA512"


AsymmetricKeyAlgorithm = Union[
    AsymmetricKeySigningAlgorithm,
    AsymmetricKeyEncryptionAlgorithm,
    AsymmetricKeyJwtAlgorithm,
    AsymmetricKeyPkiAlgorithm,
]
"""The algorithm of an asymmetric key."""


class AsymmetricKeyVersion(ItemVersion):
    public_key: Optional[EncodedPublicKey] = None


class AsymmetricKey(Key):
    type: Literal[ItemType.ASYMMETRIC_KEY] = ItemType.ASYMMETRIC_KEY
    item_versions: List[AsymmetricKeyVersion]

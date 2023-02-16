# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from typing import Optional

from pangea.response import APIRequestModel, PangeaResponseResult
from pangea.services.vault.models.common import (
    CommonGenerateRequest,
    CommonGenerateResult,
    CommonStoreRequest,
    CommonStoreResult,
    EncodedSymmetricKey,
    ItemType,
    KeyPurpose,
    SymmetricAlgorithm,
)


class SymmetricStoreRequest(CommonStoreRequest):
    managed: Optional[bool] = None
    key: EncodedSymmetricKey
    algorithm: SymmetricAlgorithm
    purpose: Optional[KeyPurpose] = None


class SymmetricStoreResult(CommonStoreResult):
    algorithm: Optional[SymmetricAlgorithm] = None  # FIXME: Remove optional once backend is updated
    key: Optional[EncodedSymmetricKey] = None


class SymmetricGenerateRequest(CommonGenerateRequest):
    algorithm: Optional[SymmetricAlgorithm] = None
    purpose: Optional[KeyPurpose] = None


class SymmetricGenerateResult(CommonGenerateResult):
    algorithm: str
    key: Optional[EncodedSymmetricKey] = None


class EncryptRequest(APIRequestModel):
    id: str
    plain_text: str


class EncryptResult(PangeaResponseResult):
    id: str
    version: int
    algorithm: str
    cipher_text: str


class DecryptRequest(APIRequestModel):
    id: str
    version: Optional[int] = None
    cipher_text: str


class DecryptResult(PangeaResponseResult):
    id: str
    version: int
    algorithm: str
    plain_text: str

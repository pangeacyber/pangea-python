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
    KeyPurpose,
    SymmetricAlgorithm,
)


class SymmetricStoreRequest(CommonStoreRequest):
    key: EncodedSymmetricKey
    algorithm: SymmetricAlgorithm
    purpose: Optional[KeyPurpose] = None


class SymmetricStoreResult(CommonStoreResult):
    algorithm: Optional[SymmetricAlgorithm] = None  # FIXME: Remove optional once backend is updated


class SymmetricGenerateRequest(CommonGenerateRequest):
    algorithm: Optional[SymmetricAlgorithm] = None
    purpose: Optional[KeyPurpose] = None


class SymmetricGenerateResult(CommonGenerateResult):
    algorithm: str


class EncryptRequest(APIRequestModel):
    id: str
    plain_text: str
    version: Optional[int] = None


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

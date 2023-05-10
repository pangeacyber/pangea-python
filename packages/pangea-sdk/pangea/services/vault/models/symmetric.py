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
    purpose: KeyPurpose


class SymmetricStoreResult(CommonStoreResult):
    algorithm: str
    purpose: str


class SymmetricGenerateRequest(CommonGenerateRequest):
    algorithm: SymmetricAlgorithm
    purpose: KeyPurpose


class SymmetricGenerateResult(CommonGenerateResult):
    algorithm: str
    purpose: str


class EncryptRequest(APIRequestModel):
    id: str
    plain_text: str
    version: Optional[int] = None
    additional_data: Optional[str]


class EncryptResult(PangeaResponseResult):
    id: str
    version: int
    algorithm: str
    cipher_text: str


class DecryptRequest(APIRequestModel):
    id: str
    cipher_text: str
    version: Optional[int] = None
    additional_data: Optional[str]


class DecryptResult(PangeaResponseResult):
    id: str
    version: int
    algorithm: str
    plain_text: str

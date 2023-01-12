# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from typing import Optional

from pangea.response import APIRequestModel, PangeaResponseResult
from pangea.services.vault.models.common import (
    CreateCommonRequest,
    CreateCommonResult,
    EncodedSymmetricKey,
    KeyAlgorithm,
    RotateCommonRequest,
    RotateCommonResult,
    StoreCommonRequest,
    StoreCommonResult,
)


class StoreKeyRequest(StoreCommonRequest):
    key: EncodedSymmetricKey
    algorithm: KeyAlgorithm
    managed: Optional[bool] = None


class StoreKeyResult(StoreCommonResult):
    algorithm: Optional[KeyAlgorithm] = None  # FIXME: Remove optional once backend is updated
    key: Optional[EncodedSymmetricKey] = None


class CreateKeyRequest(CreateCommonRequest):
    algorithm: Optional[KeyAlgorithm] = None
    managed: Optional[bool] = None


class CreateKeyResult(CreateCommonResult):
    algorithm: KeyAlgorithm
    key: Optional[EncodedSymmetricKey] = None


class EncryptRequest(APIRequestModel):
    id: str
    plain_text: str


class EncryptResult(PangeaResponseResult):
    id: str
    version: int
    algorithm: KeyAlgorithm
    cipher_text: str


class DecryptRequest(APIRequestModel):
    id: str
    version: Optional[int] = None
    cipher_text: str


class DecryptResult(PangeaResponseResult):
    id: str
    version: Optional[int] = None
    algorithm: KeyAlgorithm
    plain_text: str


class RotateKeyRequest(RotateCommonRequest):
    key: Optional[str]


class RotateKeyResult(RotateCommonResult):
    key: Optional[EncodedSymmetricKey] = None
    algorithm: KeyAlgorithm

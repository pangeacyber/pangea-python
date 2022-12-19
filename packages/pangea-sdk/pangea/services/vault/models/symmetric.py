# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from typing import Optional

from pangea.response import PangeaResponseResult
from pangea.services.vault.models.common import (
    StoreCommonRequest,
    StoreCommonResult,
    CreateCommonRequest,
    CreateCommonResult,
    KeyAlgorithm,
    RetrieveCommonRequest,
    RetrieveCommonResult,
    BaseModelConfig,
    RotateCommonRequest,
    RotateCommonResult,
)


class StoreKeyRequest(StoreCommonRequest):
    key: str
    algorithm: KeyAlgorithm
    managed: Optional[bool] = None


class StoreKeyResult(StoreCommonResult):
    algorithm: Optional[KeyAlgorithm] = None  # FIXME: Remove optional once backend is updated
    key: Optional[str] = None


class CreateKeyRequest(CreateCommonRequest):
    algorithm: Optional[KeyAlgorithm] = None
    managed: Optional[bool] = None


class CreateKeyResult(CreateCommonResult):
    algorithm: KeyAlgorithm
    key: Optional[str] = None


class RetrieveKeyRequest(RetrieveCommonRequest):
    pass


class RetrieveKeyResult(RetrieveCommonResult):
    algorithm: KeyAlgorithm
    key: Optional[str] = None
    managed: Optional[bool] = None


class EncryptRequest(BaseModelConfig):
    id: str
    plain_text: str


class EncryptResult(PangeaResponseResult):
    id: str
    version: int
    algorithm: KeyAlgorithm
    cipher_text: str


class DecryptRequest(BaseModelConfig):
    id: str
    version: Optional[int] = None
    cipher_text: str


class DecryptResult(PangeaResponseResult):
    id: str
    version: Optional[int] = None
    algorithm: KeyAlgorithm
    plain_text: str


class RotateKeyRequest(RotateCommonRequest):
    pass


class RotateKeyResult(RotateCommonResult):
    key: Optional[str] = None
    algorithm: KeyAlgorithm

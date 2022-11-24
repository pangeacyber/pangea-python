# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from typing import Optional

from pangea.response import PangeaResponseResult
from pangea.services.vault.models.common import *


class StoreKeyRequest(StoreCommonRequest):
    key: str
    algorithm: KeyAlgorithm
    managed: Optional[bool] = None


class StoreKeyResult(StoreCommonResult):
    algorithm: Optional[KeyAlgorithm] = None  # FIXME: Remove optional once backend is updated
    key: str


class CreateKeyRequest(CreateCommonRequest):
    algorithm: KeyAlgorithm
    managed: Optional[bool] = None


class CreateKeyResult(CreateCommonResult):
    key: Optional[str] = None


class RetrieveKeyResult(RetrieveCommonResult):
    key: str
    algorithm: Optional[KeyAlgorithm] = None
    managed: Optional[bool] = None


class EncryptRequest(BaseModelConfig):
    id: str
    plain_text: str


class EncryptResult(PangeaResponseResult):
    # id: str
    # version: int
    cipher_text: str


class DecryptRequest(BaseModelConfig):
    id: str
    cipher_text: str


class DecryptResult(PangeaResponseResult):
    plain_text: str


class RotateKeyResult(RotateCommonResult):
    key: Optional[str] = None

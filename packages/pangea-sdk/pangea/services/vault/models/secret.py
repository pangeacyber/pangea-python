# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import enum
from typing import Optional

from pangea.services.vault.models.common import (
    CommonGenerateRequest,
    CommonGenerateResult,
    CommonRotateRequest,
    CommonRotateResult,
    CommonStoreRequest,
    CommonStoreResult,
)


class SecretAlgorithm(str, enum.Enum):
    BASE32 = "base32"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class StoreSecretRequest(CommonStoreRequest):
    secret: str
    type: str


class StoreSecretResult(CommonStoreResult):
    secret: str


class GenerateSecretRequest(CommonGenerateRequest):
    type: str


class GenerateSecretResult(CommonGenerateResult):
    secret: str


class RotateSecretRequest(CommonRotateRequest):
    secret: str


class RotateSecretResult(CommonRotateResult):
    secret: str

# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import enum
from typing import Optional

from pangea.services.vault.models.common import (
    CreateCommonRequest,
    CreateCommonResult,
    RotateCommonRequest,
    RotateCommonResult,
    StoreCommonRequest,
    StoreCommonResult,
)


class SecretAlgorithm(str, enum.Enum):
    BASE32 = "base32"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class StoreSecretRequest(StoreCommonRequest):
    secret: str
    type: str


class StoreSecretResult(StoreCommonResult):
    secret: str


class CreateSecretRequest(CreateCommonRequest):
    type: str


class CreateSecretResult(CreateCommonResult):
    secret: str


class RotateSecretRequest(RotateCommonRequest):
    secret: str


class RotateSecretResult(RotateCommonResult):
    secret: str

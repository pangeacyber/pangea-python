# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import enum

from pangea.services.vault.models.common import (
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


class SecretStoreRequest(CommonStoreRequest):
    secret: str


class SecretStoreResult(CommonStoreResult):
    secret: str


class SecretRotateRequest(CommonRotateRequest):
    secret: str


class SecretRotateResult(CommonRotateResult):
    secret: str

# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from pangea.services.vault.models.common import (
    CommonRotateRequest,
    CommonRotateResult,
    CommonStoreRequest,
    CommonStoreResult,
)


class SecretStoreRequest(CommonStoreRequest):
    secret: str


class SecretStoreResult(CommonStoreResult):
    secret: str


class SecretRotateRequest(CommonRotateRequest):
    secret: str


class SecretRotateResult(CommonRotateResult):
    secret: str

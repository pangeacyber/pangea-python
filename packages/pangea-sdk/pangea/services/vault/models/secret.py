# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from typing import Optional

from pangea.services.vault.models.common import (
    CommonRotateRequest,
    CommonRotateResult,
    CommonStoreRequest,
    CommonStoreResult,
)


class SecretStoreRequest(CommonStoreRequest):
    retain_previous_version: Optional[bool] = None
    secret: str


class SecretStoreResult(CommonStoreResult):
    secret: str


class SecretRotateRequest(CommonRotateRequest):
    secret: str


class SecretRotateResult(CommonRotateResult):
    secret: str

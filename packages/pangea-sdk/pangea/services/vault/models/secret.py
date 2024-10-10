# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from typing import Optional

from typing_extensions import Literal

from pangea.response import APIRequestModel, PangeaDateTime
from pangea.services.vault.models.common import (
    CommonRotateRequest,
    CommonRotateResult,
    CommonStoreResult,
    Metadata,
    Tags,
)


class SecretStoreRequest(APIRequestModel):
    type: Literal["secret", "pangea_token", "pangea_client_secret", "pangea_platform_client_secret"]

    # Secret.
    secret: Optional[str] = None

    # Pangea token.
    token: Optional[str] = None

    # Pangea client secret.
    client_secret: Optional[str] = None
    client_id: Optional[str] = None
    client_secret_id: Optional[str] = None

    # Optional.
    name: Optional[str] = None
    folder: Optional[str] = None
    metadata: Optional[Metadata] = None
    tags: Optional[Tags] = None
    disabled_at: Optional[PangeaDateTime] = None


class SecretStoreResult(CommonStoreResult):
    secret: str


class SecretRotateRequest(CommonRotateRequest):
    secret: str


class SecretRotateResult(CommonRotateResult):
    secret: str

# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from typing import Optional

from pangea.response import APIRequestModel, PangeaResponseResult
from pangea.services.vault.models.common import (
    AsymmetricAlgorithm,
    CommonGenerateRequest,
    CommonGenerateResult,
    CommonStoreRequest,
    CommonStoreResult,
    EncodedPrivateKey,
    EncodedPublicKey,
    KeyPurpose,
)


class AsymmetricGenerateRequest(CommonGenerateRequest):
    algorithm: AsymmetricAlgorithm
    purpose: KeyPurpose


class AsymmetricGenerateResult(CommonGenerateResult):
    algorithm: str
    purpose: str
    public_key: EncodedPublicKey


class AsymmetricStoreRequest(CommonStoreRequest):
    algorithm: AsymmetricAlgorithm
    public_key: EncodedPublicKey
    private_key: EncodedPrivateKey
    purpose: KeyPurpose


class AsymmetricStoreResult(CommonStoreResult):
    algorithm: str
    purpose: str
    public_key: EncodedPublicKey


class SignRequest(APIRequestModel):
    id: str
    message: str
    version: Optional[int] = None


class SignResult(PangeaResponseResult):
    id: str
    version: int
    algorithm: str
    signature: str
    public_key: Optional[EncodedPublicKey] = None


class VerifyRequest(APIRequestModel):
    id: str
    message: str
    signature: str
    version: Optional[int] = None


class VerifyResult(PangeaResponseResult):
    id: str
    version: int
    algorithm: str
    valid_signature: bool

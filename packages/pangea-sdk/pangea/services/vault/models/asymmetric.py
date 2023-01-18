# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from typing import Optional

from pangea.response import APIRequestModel, PangeaResponseResult
from pangea.services.vault.models.common import (
    AsymmetricAlgorithm,
    AsymmetricPurpose,
    CommonGenerateRequest,
    CommonGenerateResult,
    CommonStoreRequest,
    CommonStoreResult,
    EncodedPrivateKey,
    EncodedPublicKey,
)


class AsymmetricGenerateRequest(CommonGenerateRequest):
    algorithm: Optional[AsymmetricAlgorithm] = None
    purpose: Optional[AsymmetricPurpose] = None


class AsymmetricGenerateResult(CommonGenerateResult):
    algorithm: AsymmetricAlgorithm
    public_key: EncodedPublicKey
    private_key: Optional[EncodedPrivateKey] = None


class AsymmetricStoreRequest(CommonStoreRequest):
    algorithm: str
    public_key: EncodedPublicKey
    private_key: EncodedPrivateKey
    purpose: Optional[AsymmetricPurpose] = None


class AsymmetricStoreResult(CommonStoreResult):
    public_key: EncodedPublicKey
    private_key: Optional[EncodedPrivateKey] = None
    algorithm: str


class SignRequest(APIRequestModel):
    id: str
    message: str


class SignResult(PangeaResponseResult):
    id: str
    version: int
    signature: str
    algorithm: AsymmetricAlgorithm
    public_key: Optional[EncodedPublicKey] = None


class VerifyRequest(APIRequestModel):
    id: str
    version: Optional[int] = None
    message: str
    signature: str


class VerifyResult(PangeaResponseResult):
    id: str
    version: int
    algorithm: AsymmetricAlgorithm
    valid_signature: bool

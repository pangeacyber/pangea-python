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
    ItemType,
    KeyPurpose,
)


class AsymmetricGenerateRequest(CommonGenerateRequest):
    algorithm: Optional[AsymmetricAlgorithm] = None
    purpose: Optional[KeyPurpose] = None


class AsymmetricGenerateResult(CommonGenerateResult):
    algorithm: str
    public_key: EncodedPublicKey
    private_key: Optional[EncodedPrivateKey] = None


class AsymmetricStoreRequest(CommonStoreRequest):
    managed: Optional[bool] = None
    type: ItemType
    algorithm: AsymmetricAlgorithm
    public_key: EncodedPublicKey
    private_key: EncodedPrivateKey
    purpose: Optional[KeyPurpose] = None


class AsymmetricStoreResult(CommonStoreResult):
    algorithm: str
    public_key: EncodedPublicKey
    private_key: Optional[EncodedPrivateKey] = None


class SignRequest(APIRequestModel):
    id: str
    message: str


class SignResult(PangeaResponseResult):
    id: str
    version: int
    signature: str
    algorithm: str
    public_key: Optional[EncodedPublicKey] = None


class VerifyRequest(APIRequestModel):
    id: str
    version: Optional[int] = None
    message: str
    signature: str


class VerifyResult(PangeaResponseResult):
    id: str
    version: int
    algorithm: str
    valid_signature: bool

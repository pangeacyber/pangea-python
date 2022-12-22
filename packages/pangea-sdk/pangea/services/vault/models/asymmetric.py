# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from typing import Optional

from pangea.response import PangeaResponseResult
from pangea.services.vault.models.common import (
    BaseModelConfig,
    CreateCommonRequest,
    CreateCommonResult,
    EncodedPrivateKey,
    EncodedPublicKey,
    KeyPairAlgorithm,
    KeyPairPurpose,
    RetrieveCommonRequest,
    RetrieveCommonResult,
    RotateCommonRequest,
    RotateCommonResult,
    StoreCommonRequest,
    StoreCommonResult,
)


class CreateKeyPairRequest(CreateCommonRequest):
    algorithm: Optional[KeyPairAlgorithm] = None
    purpose: Optional[KeyPairPurpose] = None


class CreateKeyPairResult(CreateCommonResult):
    algorithm: KeyPairAlgorithm
    public_key: EncodedPublicKey
    private_key: Optional[EncodedPrivateKey] = None


class StoreKeyPairRequest(StoreCommonRequest):
    algorithm: str
    public_key: EncodedPublicKey
    private_key: EncodedPrivateKey
    purpose: Optional[KeyPairPurpose] = None


class StoreKeyPairResult(StoreCommonResult):
    public_key: EncodedPublicKey
    private_key: Optional[EncodedPrivateKey] = None
    algorithm: str


class RetrieveKeyPairRequest(RetrieveCommonRequest):
    pass


class RetrieveKeyPairResult(RetrieveCommonResult):
    algorithm: Optional[KeyPairAlgorithm] = None
    public_key: Optional[EncodedPublicKey] = None
    private_key: Optional[EncodedPrivateKey] = None
    purpose: Optional[KeyPairPurpose] = None
    managed: Optional[bool] = None


class RotateKeyPairRequest(RotateCommonRequest):
    public_key: Optional[EncodedPublicKey] = None
    private_key: Optional[EncodedPrivateKey] = None


class RotateKeyPairResult(RotateCommonResult):
    public_key: EncodedPublicKey
    private_key: Optional[EncodedPrivateKey] = None
    algorithm: KeyPairAlgorithm


class SignRequest(BaseModelConfig):
    id: str
    message: str


class SignResult(PangeaResponseResult):
    id: str
    version: int
    signature: str
    algorithm: KeyPairAlgorithm
    public_key: Optional[EncodedPublicKey] = None


class VerifyRequest(BaseModelConfig):
    id: str
    version: Optional[int] = None
    message: str
    signature: str


class VerifyResult(PangeaResponseResult):
    id: str
    version: int
    algorithm: KeyPairAlgorithm
    valid_signature: bool

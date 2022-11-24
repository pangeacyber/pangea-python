# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import datetime
import enum
from typing import Dict, List, Optional

from pangea.response import PangeaResponseResult
from pangea.services.vault.models.common import *


class CreateKeyPairRequest(CreateCommonRequest):
    algorithm: KeyPairAlgorithm
    managed: Optional[bool] = None
    purpose: KeyPairPurpose


class CreateKeyPairResult(CreateCommonResult):
    public_key: EncodedPublicKey
    private_key: Optional[EncodedPrivateKey] = None


class StoreKeyPairRequest(StoreCommonRequest):
    public_key: EncodedPublicKey
    private_key: EncodedPrivateKey
    algorithm: str
    purpose: KeyPairPurpose
    managed: Optional[bool] = None


class StoreKeyPairResult(StoreCommonResult):
    public_key: EncodedPublicKey
    private_key: Optional[EncodedPrivateKey] = None


class RetrieveKeyPairResult(RetrieveCommonResult):
    public_key: Optional[EncodedPublicKey] = None
    private_key: Optional[EncodedPrivateKey] = None
    algorithm: Optional[KeyPairAlgorithm] = None
    purpose: Optional[KeyPairPurpose] = None
    managed: Optional[bool] = None


class RotateKeyPairResult(RotateCommonResult):
    public_key: EncodedPublicKey
    private_key: Optional[EncodedPrivateKey] = None


class SignRequest(BaseModelConfig):
    id: str
    message: str


class SignResult(PangeaResponseResult):
    id: str
    version: int
    signature: str


class VerifyRequest(BaseModelConfig):
    id: str
    version: Optional[int] = None
    message: str
    signature: str


class VerifyResult(PangeaResponseResult):
    id: str
    version: int
    signature_verified: bool


class RotateKeyPairResult(RotateCommonResult):
    public_key: EncodedPublicKey
    private_key: Optional[EncodedPrivateKey] = None

# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import datetime
from typing import Optional

from pangea.response import PangeaResponseResult
from pangea.services.vault.models.common import (
    CreateCommonRequest,
    CreateCommonResult,
    KeyPairAlgorithm,
    KeyPairPurpose,
    StoreCommonRequest,
    StoreCommonResult,
    RetrieveCommonRequest,
    RetrieveCommonResult,
    RotateCommonRequest,
    RotateCommonResult,
    BaseModelConfig,
)
from pangea.utils import format_datetime


class CreateKeyPairRequest(CreateCommonRequest):
    algorithm: Optional[KeyPairAlgorithm] = None
    purpose: Optional[KeyPairPurpose] = None


class CreateKeyPairResult(CreateCommonResult):
    algorithm: KeyPairAlgorithm
    public_key: str
    private_key: Optional[str] = None


class StoreKeyPairRequest(StoreCommonRequest):
    algorithm: str
    public_key: str
    private_key: str
    purpose: Optional[KeyPairPurpose] = None


class StoreKeyPairResult(StoreCommonResult):
    public_key: str
    private_key: Optional[str] = None
    algorithm: str


class RetrieveKeyPairRequest(RetrieveCommonRequest):
    pass


class RetrieveKeyPairResult(RetrieveCommonResult):
    algorithm: Optional[KeyPairAlgorithm] = None
    public_key: Optional[str] = None
    private_key: Optional[str] = None
    purpose: Optional[KeyPairPurpose] = None
    managed: Optional[bool] = None


class RotateKeyPairRequest(RotateCommonRequest):
    public_key: Optional[str] = None
    private_key: Optional[str] = None


class RotateKeyPairResult(RotateCommonResult):
    public_key: str
    private_key: Optional[str] = None
    algorithm: KeyPairAlgorithm


class SignRequest(BaseModelConfig):
    id: str
    message: str


class SignResult(PangeaResponseResult):
    id: str
    version: int
    signature: str
    algorithm: KeyPairAlgorithm
    public_key: Optional[str] = None


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

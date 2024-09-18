from __future__ import annotations

from typing import Literal, Optional, Union

from pangea.response import APIRequestModel, PangeaDateTime
from pangea.services.vault.models.asymmetric import (
    AsymmetricKeyEncryptionAlgorithm,
    AsymmetricKeyJwtAlgorithm,
    AsymmetricKeyPkiAlgorithm,
    AsymmetricKeyPurpose,
    AsymmetricKeySigningAlgorithm,
)
from pangea.services.vault.models.common import (
    ItemType,
    Metadata,
    RequestManualRotationState,
    RequestRotationState,
    Tags,
)
from pangea.services.vault.models.symmetric import (
    SymmetricKeyEncryptionAlgorithm,
    SymmetricKeyFpeAlgorithm,
    SymmetricKeyJwtAlgorithm,
    SymmetricKeyPurpose,
)


class CommonGenerateRequest(APIRequestModel):
    type: Literal[ItemType.ASYMMETRIC_KEY, ItemType.SYMMETRIC_KEY]
    purpose: Union[AsymmetricKeyPurpose, SymmetricKeyPurpose]
    algorithm: Union[
        AsymmetricKeySigningAlgorithm,
        AsymmetricKeyEncryptionAlgorithm,
        AsymmetricKeyJwtAlgorithm,
        AsymmetricKeyPkiAlgorithm,
        SymmetricKeyEncryptionAlgorithm,
        SymmetricKeyJwtAlgorithm,
        SymmetricKeyFpeAlgorithm,
    ]
    name: Optional[str] = None
    folder: Optional[str] = None
    metadata: Optional[Metadata] = None
    tags: Optional[Tags] = None
    rotation_frequency: Optional[str] = None
    rotation_state: Optional[RequestRotationState] = RequestRotationState.INHERITED
    disabled_at: Optional[PangeaDateTime] = None
    exportable: bool = False


class KeyStoreRequest(APIRequestModel):
    # Required.
    type: Literal[ItemType.ASYMMETRIC_KEY, ItemType.SYMMETRIC_KEY]
    purpose: Union[AsymmetricKeyPurpose, SymmetricKeyPurpose]
    algorithm: Union[
        AsymmetricKeySigningAlgorithm,
        AsymmetricKeyEncryptionAlgorithm,
        AsymmetricKeyJwtAlgorithm,
        AsymmetricKeyPkiAlgorithm,
        SymmetricKeyEncryptionAlgorithm,
        SymmetricKeyJwtAlgorithm,
        SymmetricKeyFpeAlgorithm,
    ]

    # Asymmetric.
    public_key: Optional[str] = None
    private_key: Optional[str] = None

    # Symmetric.
    key: Optional[str] = None

    # Optional.
    name: Optional[str] = None
    folder: Optional[str] = None
    metadata: Optional[Metadata] = None
    tags: Optional[Tags] = None
    rotation_frequency: Optional[str] = None
    rotation_state: Optional[RequestRotationState] = RequestRotationState.INHERITED
    disabled_at: Optional[PangeaDateTime] = None
    exportable: bool = False


class KeyRotateRequest(APIRequestModel):
    # Required.
    id: str

    # Asymmetric.
    public_key: Optional[str] = None
    private_key: Optional[str] = None

    # Symmetric.
    key: Optional[str] = None

    # Optional.
    rotation_state: RequestManualRotationState = RequestManualRotationState.DEACTIVATED

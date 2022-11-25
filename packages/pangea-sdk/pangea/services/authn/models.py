# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from typing import Any, Dict, List, NewType, Optional

from pangea.response import APIRequestModel, PangeaResponseResult

Scopes = NewType("Scopes", List[str])
Profile = NewType("Profile", Dict[str, Any])


class PasswordUpdateRequest(APIRequestModel):
    email: str
    old_secret: str
    new_secret: str


class PasswordUpdateResult(PangeaResponseResult):
    # FIXME: Update once doc is updated
    # https://dev.pangea.cloud/docs/api/authn#change-a-users-password
    pass


# https://dev.pangea.cloud/docs/api/authn#create-user
class UserCreateRequest(APIRequestModel):
    email: str
    authenticator: str
    verified: Optional[bool] = None
    require_mfa: Optional[bool] = None
    profile: Optional[Profile] = None
    scopes: Optional[Scopes] = None


class UserCreateResult(PangeaResponseResult):
    identity: str
    email: str
    profile: Profile
    id_provider: str
    mfa_provider: List[str]
    require_mfa: bool
    verified: bool
    disable: bool
    last_login_at: str


class UserDeleteRequest(APIRequestModel):
    email: str


class UserDeleteResult(PangeaResponseResult):
    # FIXME: update once documented # https://dev.pangea.cloud/docs/api/authn#delete-a-user
    pass


class UserInviteRequest(APIRequestModel):
    inviter: str
    email: str
    callback: str
    state: str
    invite_ord: Optional[str] = None
    require_mfa: Optional[bool] = None


class UserInviteResult(PangeaResponseResult):
    id: str
    inviter: str
    invite_ord: str
    email: str
    callback: str
    state: str
    require_mfa: bool
    created_at: str
    expire: str


class UserInviteDeleteRequest(APIRequestModel):
    id: str


class UserInviteDeleteResult(PangeaResponseResult):
    # FIXME: Update once documented # https://dev.pangea.cloud/docs/api/authn#delete-an-invite
    pass


class UserListRequest(APIRequestModel):
    scopes: Scopes
    glob_scopes: Scopes


class User(APIRequestModel):
    profile: Profile
    identity: str
    email: str
    scopes: Scopes


class UserListResult(PangeaResponseResult):
    users: List[User]


class UserLoginRequest(APIRequestModel):
    email: str
    secret: str
    scopes: Optional[Scopes] = None


class UserLoginResult(PangeaResponseResult):
    token: str
    id: str
    type: str
    life: int
    expire: str
    identity: str
    email: str
    scopes: Scopes
    profile: Profile
    created_at: str


class UserProfileGetRequest(APIRequestModel):
    identity: str
    email: str


class UserProfileGetResult(PangeaResponseResult):
    identity: str
    email: str
    profile: Profile
    id_provider: str
    mfa_providers: List[str]
    require_mfa: bool
    verified: bool
    disable: bool
    last_login_at: str


class UserProfileUpdateRequest(APIRequestModel):
    identity: str
    email: str
    profile: Profile
    require_mfa: Optional[bool] = None
    mfa_value: Optional[str] = None
    mfa_provider: Optional[str] = None


class UserProfileUpdateResult(PangeaResponseResult):
    identity: str
    email: str
    profile: Profile
    id_provider: str
    mfa_providers: List[str]
    require_mfa: bool
    verified: bool
    disable: bool
    last_login_at: str


class TOTPCreateRequest(APIRequestModel):
    email: str
    issuer: Optional[str] = None


class TOTPCreateResult(PangeaResponseResult):
    qr_image: str
    secret: str


class TOTPVerifyRequest(APIRequestModel):
    secret: str
    code: str


class TOTPVerifyResult(PangeaResponseResult):
    verified: bool


class OTPCreateRequest(APIRequestModel):
    email: str
    otp_provider: str


class OTPCreateResult(PangeaResponseResult):
    otp_provider: str


class OTPVerifyRequest(APIRequestModel):
    email: str
    code: str
    opt_provider: str


class OTPVerifyResult(PangeaResponseResult):
    verified: bool

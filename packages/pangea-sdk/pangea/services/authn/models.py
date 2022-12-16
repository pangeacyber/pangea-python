# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import enum
from typing import Any, Dict, List, NewType, Optional

from pangea.response import APIRequestModel, APIResponseModel, PangeaResponseResult

Scopes = NewType("Scopes", List[str])
Profile = NewType("Profile", Dict[str, Any])


class PasswordUpdateRequest(APIRequestModel):
    email: str
    old_secret: str
    new_secret: str


class PasswordUpdateResult(PangeaResponseResult):
    # https://dev.pangea.cloud/docs/api/authn#change-a-users-password
    pass


class IDProvider(str, enum.Enum):
    PASSWORD = "password"
    GOOGLE = "google"
    GITHUB = "github"
    FACEBOOK = "facebook"
    MICROSOFT_ONLINE = "microsoftonline"

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value


# https://dev.pangea.cloud/docs/api/authn#create-user
class UserCreateRequest(APIRequestModel):
    email: str
    authenticator: str
    id_provider: IDProvider
    verified: Optional[bool] = None
    require_mfa: Optional[bool] = None
    profile: Optional[Profile] = None
    scopes: Optional[Scopes] = None


class UserCreateResult(PangeaResponseResult):
    identity: str
    email: str
    profile: Profile
    id_provider: str
    require_mfa: bool
    verified: bool
    last_login_at: str
    disable: Optional[bool] = None
    mfa_provider: Optional[List[str]] = None


class UserDeleteRequest(APIRequestModel):
    email: str


class UserDeleteResult(PangeaResponseResult):
    # https://dev.pangea.cloud/docs/api/authn#delete-a-user
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
    invite_org: str
    email: str
    callback: str
    state: str
    require_mfa: bool
    created_at: str
    expire: str


class UserInvite(APIResponseModel):
    id: str
    inviter: str
    invite_org: str
    email: str
    callback: str
    state: str
    require_mfa: bool
    created_at: str
    expire: str


class UserInviteListResult(PangeaResponseResult):
    invites: List[UserInvite]


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
    scopes: Optional[Scopes] = None
    profile: Profile
    created_at: str


class UserProfileGetRequest(APIRequestModel):
    identity: Optional[str] = None
    email: Optional[str] = None


class UserProfileGetResult(PangeaResponseResult):
    identity: str
    email: str
    profile: Profile
    id_provider: str
    mfa_providers: List[str]
    require_mfa: bool
    verified: bool
    last_login_at: str
    disable: Optional[bool] = None


class UserProfileUpdateRequest(APIRequestModel):
    profile: Profile
    identity: Optional[str] = None
    email: Optional[str] = None
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
    last_login_at: str
    disable: Optional[bool] = None

# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import enum
from typing import Dict, List, NewType, Optional, Union

from pangea.response import APIRequestModel, APIResponseModel, PangeaResponseResult
from pangea.services.vault.models.common import JWK, JWKec, JWKrsa

Scopes = NewType("Scopes", List[str])
Profile = NewType("Profile", Dict[str, str])


class UserPasswordResetRequest(APIRequestModel):
    user_id: str
    new_password: str


class UserPasswordResetResult(PangeaResponseResult):
    pass


class ClientPasswordChangeRequest(APIRequestModel):
    token: str
    old_password: str
    new_password: str


class ClientPasswordChangeResult(PangeaResponseResult):
    pass


class ClientTokenCheckRequest(APIRequestModel):
    token: str


class ClientTokenCheckResult(PangeaResponseResult):
    id: str
    type: str
    life: int
    expire: str
    identity: str
    email: str
    scopes: Scopes
    profile: Profile
    created_at: str


class IDProvider(str, enum.Enum):
    FACEBOOK = "facebook"
    GITHUB = "github"
    GOOGLE = "google"
    MICROSOFT = "microsoftonline"
    PASSWORD = "password"

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value


class MFAProvider(enum.Enum):
    TOTP = "totp"
    EMAIL_OTP = "email_otp"
    SMS_OTP = "sms_otp"

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value


class FlowType(enum.Enum):
    SIGNIN = "signin"
    SIGNUP = "signup"

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value


class ItemOrder(enum.Enum):
    ASC = "asc"
    DESC = "desc"

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value


class SessionListOrderBy(enum.Enum):
    ID = "id"
    CREATED_AT = "created_at"
    TYPE = "type"
    EMAIL = "email"
    EXPIRE = "expire"
    ACTIVE_TOKEN_ID = "active_token_id"

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value


class UserListOrderBy(enum.Enum):
    ID = "id"
    CREATED_AT = "created_at"
    EMAIL = "email"
    LAST_LOGIN_AT = "last_login_at"
    ACTIVE_TOKEN_ID = "active_token_id"

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
    id: str
    email: str
    profile: Profile
    id_providers: Optional[List[str]] = None
    require_mfa: bool
    verified: bool
    last_login_at: Optional[str]
    disabled: Optional[bool] = None
    mfa_providers: Optional[List[str]] = None


class UserDeleteRequest(APIRequestModel):
    email: Optional[str] = None
    id: Optional[str] = None


class UserDeleteResult(PangeaResponseResult):
    # https://dev.pangea.cloud/docs/api/authn#delete-a-user
    pass


class UserInviteRequest(APIRequestModel):
    inviter: str
    email: str
    callback: str
    state: str
    require_mfa: Optional[bool] = None


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


class UserInviteResult(PangeaResponseResult, UserInvite):
    pass


class UserInviterOrderBy(enum.Enum):
    ID = "id"
    CREATED_AT = "created_at"
    EMAIL = "email"
    TYPE = "type"
    EXPIRE = "expire"
    CALLBACK = "callback"
    STATE = "state"
    INVITER = "inviter"
    INVITE_ORG = "invite_org"

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value


class UserInviteListRequest(APIRequestModel):
    filter: Optional[Dict] = None
    last: Optional[str] = None
    order: Optional[ItemOrder] = None
    order_by: Optional[UserInviterOrderBy] = None
    size: Optional[int] = None


class UserInviteListResult(PangeaResponseResult):
    invites: List[UserInvite]


class UserInviteDeleteRequest(APIRequestModel):
    id: str


class UserInviteDeleteResult(PangeaResponseResult):
    pass


class UserListRequest(APIRequestModel):
    use_new: bool = True  # Temporary field, need to be true
    filter: Optional[Dict] = None
    last: Optional[str] = None
    order: Optional[ItemOrder] = None
    order_by: Optional[UserListOrderBy] = None
    size: Optional[int] = None


class User(APIRequestModel):
    id: str
    email: str
    profile: Profile
    scopes: Optional[Scopes] = None
    id_providers: List[str] = []
    mfa_providers: List[str] = []
    require_mfa: bool
    verified: bool
    disabled: bool
    last_login_at: Optional[str] = None
    created_at: str


class UserListResult(PangeaResponseResult):
    users: List[User]
    last: str
    count: int


class UserLoginPasswordRequest(APIRequestModel):
    email: str
    password: str
    extra_profile: Optional[Profile] = None


class LoginToken(APIResponseModel):
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


# {'token': 'ptr_mjl7snb74cnxjtu7lypouafrayyydlfu',
# 'id': 'pmt_557qjw27bokucj2ccxyqnbo2vxq6dci2',
# 'type': 'session',
# 'life': 172799,
# 'expire': '2023-02-11T20:16:52.750157Z',
# 'id': 'pui_a5dhmqsmpayxcohb2intdidwttkxxza2',
# 'email': 'andres.tournour+test2591827@pangea.cloud',
# 'profile': {},
# 'created_at': '2023-02-09T20:16:52.753810Z'}


class UserLoginResult(PangeaResponseResult):
    refresh_token: LoginToken
    active_token: Optional[LoginToken] = None


class UserLoginSocialRequest(APIRequestModel):
    provider: IDProvider
    email: str
    social_id: str
    extra_profile: Optional[Profile] = None


class UserProfileGetRequest(APIRequestModel):
    id: Optional[str] = None
    email: Optional[str] = None


class UserProfileGetResult(PangeaResponseResult):
    id: str
    email: str
    profile: Profile
    id_providers: Optional[List[str]] = None
    mfa_providers: List[str]
    require_mfa: bool
    verified: bool
    disabled: Optional[bool] = None
    last_login_at: Optional[str] = None
    created_at: str


class UserProfileUpdateRequest(APIRequestModel):
    profile: Profile
    id: Optional[str] = None
    email: Optional[str] = None


class UserProfileUpdateResult(PangeaResponseResult):
    id: str
    email: str
    profile: Profile
    id_providers: Optional[List[str]] = None
    mfa_providers: List[str]
    require_mfa: bool
    verified: bool
    last_login_at: Optional[str] = None
    disabled: Optional[bool] = None
    created_at: str


class UserUpdateRequest(APIRequestModel):
    id: Optional[str] = None
    email: Optional[str] = None
    authenticator: Optional[str] = None
    disabled: Optional[bool] = None
    require_mfa: Optional[bool] = None
    verified: Optional[bool] = None


class UserUpdateResult(PangeaResponseResult):
    id: str
    email: str
    profile: Profile
    scopes: Optional[Scopes] = None
    id_providers: Optional[List[str]] = None
    mfa_providers: Optional[List[str]] = None
    require_mfa: bool
    verified: bool
    disabled: bool
    last_login_at: Optional[str] = None
    created_at: str


class ClientUserinfoResult(PangeaResponseResult):
    active_token: Optional[LoginToken] = None
    refresh_token: LoginToken


class ClientUserinfoRequest(APIRequestModel):
    code: str


class ClientJWKSResult(PangeaResponseResult):
    keys: List[Union[JWKec, JWKrsa, JWK]]


#   - path: authn::/v1/flow/complete
# https://dev.pangea.cloud/docs/api/authn#complete-a-login-or-signup-flow
class FlowCompleteRequest(APIRequestModel):
    flow_id: str


class FlowCompleteResult(PangeaResponseResult):
    refresh_token: LoginToken
    login_token: LoginToken


#   - path: authn::/v1/flow/enroll/mfa/complete
# https://dev.pangea.cloud/docs/api/authn#complete-mfa-enrollment-by-verifying-a-trial-mfa-code
class FlowEnrollMFACompleteRequest(APIRequestModel):
    flow_id: str
    code: str
    cancel: Optional[bool] = None


class EnrollMFAStart:
    mfa_providers: List[str]


class TOTPsecret:
    qr_image: str
    secret: str


class EnrollMFAComplete:
    totp_secret: TOTPsecret


class SocialSignup:
    redirect_uri: str


class PasswordSignup:
    password_chars_min: int
    password_chars_max: int
    password_lower_min: int
    passwrod_upper_min: int
    password_punct_min: int


class VerifyCaptcha:
    site_key: str


class VerifyMFAStart:
    mfa_providers: List[str]


class VerifyPassword:
    password_chars_min: int
    password_chars_max: int
    password_lower_min: int
    passwrod_upper_min: int
    password_punct_min: int


class Signup:
    social_signup: SocialSignup
    password_signup: PasswordSignup


class VerifySocial:
    redirect_uri: str


class CommonFlowResult(PangeaResponseResult):
    flow_id: str
    next_step: str
    error: Optional[str] = None
    complete: Optional[dict] = None
    enroll_mfa_start: Optional[EnrollMFAStart] = None
    enroll_mfa_complete: Optional[EnrollMFAComplete] = None
    signup: Optional[Signup] = None
    verify_captcha: Optional[VerifyCaptcha] = None
    verify_email: Optional[dict] = None
    verify_mfa_start: Optional[VerifyMFAStart] = None
    verify_mfa_complete: Optional[dict] = None
    verify_password: Optional[VerifyPassword] = None
    verify_social: Optional[VerifySocial] = None


class FlowResetPasswordRequest(APIRequestModel):
    flow_id: str
    password: str
    cancel: Optional[bool] = None
    cb_state: Optional[str] = None
    cb_code: Optional[str] = None


class FlowResetPasswordResult(CommonFlowResult):
    pass


class FlowEnrollMFAcompleteResult(CommonFlowResult):
    pass


#   - path: authn::/v1/flow/enroll/mfa/start
# https://dev.pangea.cloud/docs/api/authn#start-the-process-of-enrolling-an-mfa
class FlowEnrollMFAStartRequest(APIRequestModel):
    flow_id: str
    mfa_provider: MFAProvider
    phone: Optional[str] = None


class FlowEnrollMFAStartResult(CommonFlowResult):
    pass


#   - path: authn::/v1/flow/signup/password
# https://dev.pangea.cloud/docs/api/authn#signup-a-new-account-using-a-password
class FlowSignupPasswordRequest(APIRequestModel):
    flow_id: str
    password: str
    first_name: str
    last_name: str


class FlowSignupPasswordResult(CommonFlowResult):
    pass


#   - path: authn::/v1/flow/signup/social
# https://dev.pangea.cloud/docs/api/authn#signup-a-new-account-using-a-social-provider
class FlowSignupSocialRequest(APIRequestModel):
    flow_id: str
    cb_state: str
    cb_code: str


class FlowSignupSocialResult(CommonFlowResult):
    pass


#   - path: authn::/v1/flow/start
# https://dev.pangea.cloud/docs/api/authn#start-a-new-signup-or-signin-flow
class FlowStartRequest(APIRequestModel):
    cb_uri: Optional[str] = None
    email: Optional[str] = None
    flow_types: Optional[List[FlowType]] = None
    provider: Optional[IDProvider] = None


class FlowStartResult(CommonFlowResult):
    pass


#   - path: authn::/v1/flow/verify/captcha
# https://dev.pangea.cloud/docs/api/authn#verify-a-captcha-during-a-signup-or-signin-flow
class FlowVerifyCaptchaRequest(APIRequestModel):
    flow_id: str
    code: str


class FlowVerifyCaptchaResult(CommonFlowResult):
    pass


#   - path: authn::/v1/flow/verify/email
# https://dev.pangea.cloud/docs/api/authn#verify-an-email-address-during-a-signup-or-signin-flow
class FlowVerifyEmailRequest(APIRequestModel):
    flow_id: str
    cb_state: Optional[str] = None
    cb_code: Optional[str] = None


class FlowVerifyEmailResult(CommonFlowResult):
    pass


#   - path: authn::/v1/flow/verify/mfa/complete
# https://dev.pangea.cloud/docs/api/authn#complete-mfa-verification
class FlowVerifyMFACompleteRequest(APIRequestModel):
    flow_id: str
    code: Optional[str] = None
    cancel: Optional[bool] = None


class FlowVerifyMFACompleteResult(CommonFlowResult):
    pass


#   - path: authn::/v1/flow/verify/mfa/start
# https://dev.pangea.cloud/docs/api/authn#start-the-process-of-mfa-verification
class FlowVerifyMFAStartRequest(APIRequestModel):
    flow_id: str
    mfa_provider: MFAProvider


class FlowVerifyMFAStartResult(CommonFlowResult):
    pass


#   - path: authn::/v1/flow/verify/password
# https://dev.pangea.cloud/docs/api/authn#sign-in-with-a-password
class FlowVerifyPasswordRequest(APIRequestModel):
    flow_id: str
    password: Optional[str] = None
    cancel: Optional[bool] = None


class FlowVerifyPasswordResult(CommonFlowResult):
    pass


#   - path: authn::/v1/flow/verify/social
# https://dev.pangea.cloud/docs/api/authn#signin-with-a-social-provider
class FlowVerifySocialRequest(APIRequestModel):
    flow_id: str
    cb_state: str
    cb_code: str


class FlowVerifySocialResult(CommonFlowResult):
    pass


#   - path: authn::/v1/user/mfa/delete
# https://dev.pangea.cloud/docs/api/authn#delete-mfa-enrollment-for-a-user
class UserMFADeleteRequest(APIRequestModel):
    user_id: str
    mfa_provider: MFAProvider


class UserMFADeleteResult(PangeaResponseResult):
    pass


#   - path: authn::/v1/user/mfa/enroll
# https://dev.pangea.cloud/docs/api/authn#enroll-mfa-for-a-user
class UserMFAEnrollRequest(APIRequestModel):
    user_id: str
    mfa_provider: MFAProvider
    code: str


class UserMFAEnrollResult(PangeaResponseResult):
    pass


#   - path: authn::/v1/user/mfa/start
# https://dev.pangea.cloud/docs/api/authn#start-mfa-verification-for-a-user
class UserMFAStartRequest(APIRequestModel):
    user_id: str
    mfa_provider: MFAProvider
    enroll: Optional[bool] = None
    phone: Optional[str] = None


class UserMFAStartTOTPSecret:
    qr_image: str
    secret: str


class UserMFAStartResult(PangeaResponseResult):
    totp_secret: Optional[UserMFAStartTOTPSecret] = None


#   - path: authn::/v1/user/mfa/verify
# https://dev.pangea.cloud/docs/api/authn#verify-an-mfa-code
class UserMFAverifyRequest(APIRequestModel):
    user_id: str
    mfa_provider: MFAProvider
    code: str


class UserMFAVerifyResult(PangeaResponseResult):
    pass


#   - path: authn::/v1/user/verify
# https://dev.pangea.cloud/docs/api/authn#verify-a-user
class UserVerifyRequest(APIRequestModel):
    id_provider: IDProvider
    email: str
    authenticator: str


class UserVerifyResult(PangeaResponseResult):
    id: str
    email: str
    profile: Profile
    scopes: Scopes
    id_providers: Optional[List[str]] = None
    mfa_providers: List[str]
    require_mfa: bool
    verified: bool
    disabled: bool
    last_login_at: Optional[str] = None
    created_at: str


class ClientSessionInvalidateRequest(APIRequestModel):
    token: str
    session_id: str


class ClientSessionInvalidateResult(PangeaResponseResult):
    pass


class ClientSessionListRequest(APIRequestModel):
    token: str
    filter: Optional[Dict] = None
    last: Optional[str] = None
    order: Optional[ItemOrder] = None
    order_by: Optional[SessionListOrderBy] = None
    size: Optional[int] = None


class SessionToken(APIResponseModel):
    id: str
    type: str
    life: int
    expire: str
    identity: str
    email: str
    scopes: Scopes
    profile: Profile
    created_at: str


class SessionItem(APIResponseModel):
    id: str
    type: str
    life: int
    expire: str
    id: str
    email: str
    scopes: Optional[Scopes] = None
    profile: Profile
    created_at: str
    active_token: Optional[SessionToken] = None


class ClientSessionListResults(PangeaResponseResult):
    sessions: List[SessionItem]
    last: str


class SessionListResults(PangeaResponseResult):
    sessions: List[SessionItem]
    last: str


class ClientSessionLogoutRequest(APIRequestModel):
    token: str


class ClientSessionLogoutResult(PangeaResponseResult):
    pass


class ClientSessionRefreshRequest(APIRequestModel):
    refresh_token: str
    user_token: Optional[str] = None


class ClientSessionRefreshResult(PangeaResponseResult):
    refresh_token: LoginToken
    active_token: Optional[LoginToken] = None


class SessionInvalidateRequest(APIRequestModel):
    session_id: str


class SessionInvalidateResult(PangeaResponseResult):
    pass


class SessionListRequest(APIRequestModel):
    filter: Optional[Dict] = None
    last: Optional[str] = None
    order: Optional[ItemOrder] = None
    order_by: Optional[SessionListOrderBy] = None
    size: Optional[int] = None


class SessionLogoutRequest(APIRequestModel):
    user_id: str


class SessionLogoutResult(PangeaResponseResult):
    pass

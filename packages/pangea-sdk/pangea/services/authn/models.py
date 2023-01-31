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
    last_login_at: Optional[str]
    disabled: Optional[bool] = None
    mfa_providers: Optional[List[str]] = None


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
    disabled: Optional[bool] = None


class UserProfileUpdateRequest(APIRequestModel):
    profile: Profile
    identity: Optional[str] = None
    email: Optional[str] = None
    require_mfa: Optional[bool] = None
    mfa_value: Optional[str] = None
    mfa_providers: Optional[str] = None


class UserProfileUpdateResult(PangeaResponseResult):
    identity: str
    email: str
    profile: Profile
    id_provider: str
    mfa_providers: List[str]
    require_mfa: bool
    verified: bool
    last_login_at: str
    disabled: Optional[bool] = None


class UserUpdateRequest(APIRequestModel):
    identity: Optional[str] = None
    email: Optional[str] = None
    authenticator: Optional[str] = None
    disabled: Optional[bool] = None
    require_mfa: Optional[bool] = None


class UserUpdateResult(PangeaResponseResult):
    identity: str
    email: str
    profile: Profile
    scopes: Optional[Scopes] = None
    id_provider: IDProvider
    mfa_providers: Optional[List[str]] = None
    require_mfa: bool
    verified: bool
    disabled: bool
    last_login_at: str


class UserinfoResult(PangeaResponseResult):
    token: str
    id: str
    type: str
    life: int
    expire: str
    identity: str
    email: str
    scope: Scopes
    profile: Profile
    created_at: str


class UserinfoRequest(APIRequestModel):
    code: str


#   - path: authn::/v1/flow/complete
# https://dev.pangea.cloud/docs/api/authn#complete-a-login-or-signup-flow
class FlowCompleteRequest(APIRequestModel):
    flow_id: str


class FlowCompleteResult(PangeaResponseResult):
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
    sike_key: str


class VerifyMFAStart:
    mfa_providers: List[str]


class VerifyPassword:
    password_chars_min: int
    password_chars_max: int
    password_lower_min: int
    passwrod_upper_min: int
    password_punct_min: int


class SignUp:
    social_signup: SocialSignup
    password_signup: PasswordSignup


class VerifySocial:
    redirect_uri: str


class CommonFlowResult(PangeaResponseResult):
    flow_id: str
    error: str
    next_step: str
    complete: dict
    enroll_mfa_start: EnrollMFAStart
    enroll_mfa_complete: EnrollMFAComplete
    signup: SignUp
    verify_captcha: VerifyCaptcha
    verify_email: dict
    verify_mfa_start: VerifyMFAStart
    verify_mfa_complete: dict
    verify_password: VerifyPassword
    verify_social: VerifySocial


class FlowEnrollMFAcompleteResult(CommonFlowResult):
    pass


#   - path: authn::/v1/flow/enroll/mfa/start
# https://dev.pangea.cloud/docs/api/authn#start-the-process-of-enrolling-an-mfa
class FlowEnrollMFAStartRequest(APIRequestModel):
    flow_id: str
    mfa_provider: MFAProvider


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
    cb_uri: str
    email: Optional[str] = None
    flow_types: Optional[List[str]] = None


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
    cb_state: str
    cb_code: str


class FlowVerifyEmailResult(CommonFlowResult):
    pass


#   - path: authn::/v1/flow/verify/mfa/complete
# https://dev.pangea.cloud/docs/api/authn#complete-mfa-verification
class FlowVerifyMFACompleteRequest(APIRequestModel):
    flow_id: str
    code: str


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
    password: str


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


class UserMFAStartResult(PangeaResponseResult):
    pass


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
    identity: str
    email: str
    profile: Profile
    scopes: Scopes
    id_provider: IDProvider
    require_mfa: bool
    verified: bool
    disabled: bool
    last_login_at: str

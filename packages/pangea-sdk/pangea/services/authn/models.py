# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import enum
from typing import Dict, List, NewType, Optional, Union

import pangea.services.intel as im
from pangea.response import APIRequestModel, APIResponseModel, PangeaResponseResult
from pangea.services.vault.models.common import JWK, JWKec, JWKrsa

Scopes = NewType("Scopes", List[str])


class Profile(Dict[str, str]):
    first_name: str
    last_name: str
    phone: Optional[str] = None


class ClientPasswordChangeRequest(APIRequestModel):
    token: str
    old_password: str
    new_password: str


class ClientPasswordChangeResult(PangeaResponseResult):
    pass


class ClientTokenCheckRequest(APIRequestModel):
    token: str


class IPIntelligence(PangeaResponseResult):
    is_bad: bool
    is_vpn: bool
    is_proxy: bool
    reputation: im.IPReputationData
    geolocation: im.IPGeolocateData


class DomainIntelligence(PangeaResponseResult):
    is_bad: bool
    reputation: im.DomainReputationData


class Intelligence(PangeaResponseResult):
    embargo: bool
    ip_intel: IPIntelligence
    domain_intel: DomainIntelligence
    user_intel: bool


class SessionToken(APIResponseModel):
    id: str
    type: str
    life: int
    expire: str
    identity: str
    email: str
    scopes: Optional[Scopes] = None
    profile: Profile
    created_at: str
    intelligence: Optional[Intelligence] = None


class LoginToken(SessionToken):
    token: str


class ClientTokenCheckResult(LoginToken):
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


class Authenticator(APIResponseModel):
    id: str
    type: str
    enable: bool
    provider: Optional[str] = None
    rpid: Optional[str] = None
    phase: Optional[str] = None


class User(PangeaResponseResult):
    id: str
    email: str
    profile: Profile
    verified: bool
    disabled: bool
    accepted_eula_id: Optional[str] = None
    accepted_privacy_policy_id: Optional[str] = None
    last_login_at: Optional[str] = None
    created_at: str
    login_count: int
    last_login_ip: Optional[str] = None
    last_login_city: Optional[str] = None
    last_login_country: Optional[str] = None
    authenticators: List[Authenticator] = []


class UserCreateRequest(APIRequestModel):
    email: str
    profile: Profile


class UserCreateResult(User):
    pass


class UserDeleteRequest(APIRequestModel):
    email: Optional[str] = None
    id: Optional[str] = None


class UserDeleteResult(PangeaResponseResult):
    pass


class UserListFilter(APIRequestModel):
    accepted_eula_id: Optional[str] = None
    accepted_eula_id__contains: Optional[List[str]] = None
    accepted_eula_id__in: Optional[List[str]] = None
    created_at: Optional[str] = None
    created_at__gt: Optional[str] = None
    created_at__gte: Optional[str] = None
    created_at__lt: Optional[str] = None
    created_at__lte: Optional[str] = None
    disabled: Optional[bool] = None
    email: Optional[str] = None
    email__contains: Optional[List[str]] = None
    email__in: Optional[List[str]] = None
    id: Optional[str] = None
    id__contains: Optional[List[str]] = None
    id__in: Optional[List[str]] = None
    last_login_at: Optional[str] = None
    last_login_at__gt: Optional[str] = None
    last_login_at__gte: Optional[str] = None
    last_login_at__lt: Optional[str] = None
    last_login_at__lte: Optional[str] = None
    last_login_ip: Optional[str] = None
    last_login_ip__contains: Optional[List[str]] = None
    last_login_ip__in: Optional[List[str]] = None
    last_login_city: Optional[str] = None
    last_login_city__contains: Optional[List[str]] = None
    last_login_city__in: Optional[List[str]] = None
    last_login_country: Optional[str] = None
    last_login_country__contains: Optional[List[str]] = None
    last_login_country__in: Optional[List[str]] = None
    login_count: Optional[int] = None
    login_count__gt: Optional[int] = None
    login_count__gte: Optional[int] = None
    login_count__lt: Optional[int] = None
    login_count__lte: Optional[int] = None
    require_mfa: Optional[bool] = None
    scopes: Optional[List[str]] = None
    verified: Optional[bool] = None


class UserListRequest(APIRequestModel):
    filter: Optional[Union[Dict, UserListFilter]] = None
    last: Optional[str] = None
    order: Optional[ItemOrder] = None
    order_by: Optional[UserListOrderBy] = None
    size: Optional[int] = None


class UserListResult(PangeaResponseResult):
    users: List[User]
    last: Optional[str] = None
    count: int


class UserInviteRequest(APIRequestModel):
    inviter: str
    email: str
    callback: str
    state: str


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


class UserInviteListFilter(APIRequestModel):
    callback: Optional[str] = None
    callback__contains: Optional[List[str]] = None
    callback__in: Optional[List[str]] = None
    created_at: Optional[str] = None
    created_at__gt: Optional[str] = None
    created_at__gte: Optional[str] = None
    created_at__lt: Optional[str] = None
    created_at__lte: Optional[str] = None
    email: Optional[str] = None
    email__contains: Optional[List[str]] = None
    email__in: Optional[List[str]] = None
    expire: Optional[str] = None
    expire__gt: Optional[str] = None
    expire__gte: Optional[str] = None
    expire__lt: Optional[str] = None
    expire__lte: Optional[str] = None
    id: Optional[str] = None
    id__contains: Optional[List[str]] = None
    id__in: Optional[List[str]] = None
    invite_org: Optional[str] = None
    invite_org__contains: Optional[List[str]] = None
    invite_org__in: Optional[List[str]] = None
    inviter: Optional[str] = None
    inviter__contains: Optional[List[str]] = None
    inviter__in: Optional[List[str]] = None
    is_signup: Optional[bool] = None
    require_mfa: Optional[bool] = None
    state: Optional[str] = None
    state__contains: Optional[List[str]] = None
    state__in: Optional[List[str]] = None


class UserInviteListRequest(APIRequestModel):
    filter: Optional[Union[Dict, UserInviteListFilter]] = None
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


class UserProfileGetRequest(APIRequestModel):
    id: Optional[str] = None
    email: Optional[str] = None


class UserProfileGetResult(User):
    pass


class UserProfileUpdateRequest(APIRequestModel):
    profile: Profile
    id: Optional[str] = None
    email: Optional[str] = None


class UserProfileUpdateResult(User):
    pass


class UserUpdateRequest(APIRequestModel):
    id: Optional[str] = None
    email: Optional[str] = None
    disabled: bool


class UserUpdateResult(User):
    pass


class ClientUserinfoResult(PangeaResponseResult):
    active_token: Optional[LoginToken] = None
    refresh_token: LoginToken


class ClientUserinfoRequest(APIRequestModel):
    code: str


class ClientJWKSResult(PangeaResponseResult):
    keys: List[Union[JWKec, JWKrsa, JWK]]


class UserAuthenticatorsDeleteRequest(APIRequestModel):
    id: Optional[str] = None
    email: Optional[str] = None
    authenticator_id: str


class UserAuthenticatorsDeleteResult(PangeaResponseResult):
    pass


class UserAuthenticatorsListRequest(APIRequestModel):
    email: Optional[str] = None
    id: Optional[str] = None


class UserAuthenticatorsListResult(PangeaResponseResult):
    authenticators: List[Authenticator]


class FlowCompleteRequest(APIRequestModel):
    flow_id: str


class FlowCompleteResult(PangeaResponseResult):
    refresh_token: LoginToken
    active_token: LoginToken


class FlowChoiceItem(APIResponseModel):
    choice: str
    data: Dict = {}


class CommonFlowResult(PangeaResponseResult):
    flow_id: str
    flow_type: List[str] = []
    email: Optional[str] = None
    disclaimer: Optional[str] = None
    flow_phase: str
    flow_choices: List[FlowChoiceItem] = []


class FlowChoice(enum.Enum):
    AGREEMENTS = "agreements"
    CAPTCHA = "captcha"
    EMAIL_OTP = "email_otp"
    MAGICLINK = "magiclink"
    PASSWORD = "password"
    PROFILE = "profile"
    PROVISIONAL_ENROLLMENT = "provisional_enrollment"
    RESET_PASSWORD = "reset_password"
    SET_EMAIL = "set_mail"
    SET_PASSWORD = "set_password"
    SMS_OTP = "sms_otp"
    SOCIAL = "social"
    TOTP = "totp"
    VERIFY_EMAIL = "verify_email"

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value


class FlowRestartDataSMSOTP(APIRequestModel):
    phone: str


FlowRestartData = Union[Dict, FlowRestartDataSMSOTP]


class FlowRestartRequest(APIRequestModel):
    flow_id: str
    choice: FlowChoice
    data: FlowRestartData


class FlowRestartResult(CommonFlowResult):
    pass


class FlowStartRequest(APIRequestModel):
    cb_uri: Optional[str] = None
    email: Optional[str] = None
    flow_types: Optional[List[FlowType]] = None
    invitation: Optional[str] = None


class FlowStartResult(CommonFlowResult):
    pass


class FlowUpdateDataAgreements(APIRequestModel):
    agreed: List[str]


class FlowUpdateDataCaptcha(APIRequestModel):
    code: str


class FlowUpdateDataEmailOTP(APIResponseModel):
    code: str


class FlowUpdateDataMagiclink(APIRequestModel):
    state: str
    code: str


class FlowUpdateDataPassword(APIRequestModel):
    password: str


class FlowUpdateDataProfile(APIRequestModel):
    profile: Profile


class FlowUpdateDataProvisionalEnrollment(APIRequestModel):
    state: str
    code: str


class FlowUpdateDataResetPassword(APIRequestModel):
    state: str
    code: str


class FlowUpdateDataSetEmail(APIRequestModel):
    email: str


class FlowUpdateDataSetPassword(APIRequestModel):
    password: str


class FlowUpdateDataSMSOTP(APIRequestModel):
    code: str


class FlowUpdateDataSocialProvider(APIRequestModel):
    social_provider: str
    uri: str


class FlowUpdateDataTOTP(APIRequestModel):
    code: str


class FlowUpdateDataVerifyEmail(APIRequestModel):
    state: str
    code: str


FlowUpdateData = Union[
    Dict,
    FlowUpdateDataAgreements,
    FlowUpdateDataCaptcha,
    FlowUpdateDataEmailOTP,
    FlowUpdateDataMagiclink,
    FlowUpdateDataPassword,
    FlowUpdateDataProfile,
    FlowUpdateDataProvisionalEnrollment,
    FlowUpdateDataResetPassword,
    FlowUpdateDataSetEmail,
    FlowUpdateDataSetPassword,
    FlowUpdateDataSMSOTP,
    FlowUpdateDataSocialProvider,
    FlowUpdateDataTOTP,
    FlowUpdateDataVerifyEmail,
]


class FlowUpdateRequest(APIRequestModel):
    flow_id: str
    choice: FlowChoice
    data: FlowUpdateData


class FlowUpdateResult(CommonFlowResult):
    pass


class ClientSessionInvalidateRequest(APIRequestModel):
    token: str
    session_id: str


class ClientSessionInvalidateResult(PangeaResponseResult):
    pass


class SessionListFilter(APIRequestModel):
    active_token_id: Optional[str] = None
    active_token_id__contains: Optional[List[str]] = None
    active_token_id__in: Optional[List[str]] = None
    created_at: Optional[str] = None
    created_at__gt: Optional[str] = None
    created_at__gte: Optional[str] = None
    created_at__lt: Optional[str] = None
    created_at__lte: Optional[str] = None
    email: Optional[str] = None
    email__contains: Optional[List[str]] = None
    email__in: Optional[List[str]] = None
    expire: Optional[str] = None
    expire__gt: Optional[str] = None
    expire__gte: Optional[str] = None
    expire__lt: Optional[str] = None
    expire__lte: Optional[str] = None
    id: Optional[str] = None
    id__contains: Optional[List[str]] = None
    id__in: Optional[List[str]] = None
    identity: Optional[str] = None
    identity__contains: Optional[List[str]] = None
    identity__in: Optional[List[str]] = None
    scopes: Optional[List[str]] = None
    type: Optional[str] = None
    type__contains: Optional[List[str]] = None
    type__in: Optional[List[str]] = None


class ClientSessionListRequest(APIRequestModel):
    token: str
    filter: Optional[Union[Dict, SessionListFilter]] = None
    last: Optional[str] = None
    order: Optional[ItemOrder] = None
    order_by: Optional[SessionListOrderBy] = None
    size: Optional[int] = None


class SessionItem(APIResponseModel):
    id: str
    type: str
    life: int
    expire: str
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
    filter: Optional[Union[Dict, SessionListFilter]] = None
    last: Optional[str] = None
    order: Optional[ItemOrder] = None
    order_by: Optional[SessionListOrderBy] = None
    size: Optional[int] = None


class SessionLogoutRequest(APIRequestModel):
    user_id: str


class SessionLogoutResult(PangeaResponseResult):
    pass


class AgreementType(enum.Enum):
    EULA = "eula"
    PRIVACY_POLICY = "privacy_policy"

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value


class AgreementCreateRequest(APIRequestModel):
    type: AgreementType
    name: str
    text: str
    active: Optional[bool] = None


class AgreementInfo(PangeaResponseResult):
    type: str
    id: str
    created_at: str
    updated_at: str
    published_at: Optional[str] = None
    name: str
    text: str
    active: bool


class AgreementCreateResult(AgreementInfo):
    pass


class AgreementDeleteRequest(APIRequestModel):
    type: AgreementType
    id: str


class AgreementDeleteResult(PangeaResponseResult):
    pass


class AgreementListOrderBy(enum.Enum):
    ID = "id"
    CREATED_AT = "created_at"
    NAME = "name"
    TEXT = "text"

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value


class AgreementListFilter(APIRequestModel):
    active: Optional[bool] = None
    created_at: Optional[str] = None
    created_at__gt: Optional[str] = None
    created_at__gte: Optional[str] = None
    created_at__lt: Optional[str] = None
    created_at__lte: Optional[str] = None
    published_at: Optional[str] = None
    published_at__gt: Optional[str] = None
    published_at__gte: Optional[str] = None
    published_at__lt: Optional[str] = None
    published_at__lte: Optional[str] = None
    type: Optional[str] = None
    type__contains: Optional[List[str]] = None
    type__in: Optional[List[str]] = None
    id: Optional[str] = None
    id__contains: Optional[List[str]] = None
    id__in: Optional[List[str]] = None
    name: Optional[str] = None
    name__contains: Optional[List[str]] = None
    name__in: Optional[List[str]] = None
    text: Optional[str] = None
    text__contains: Optional[List[str]] = None
    text__in: Optional[List[str]] = None


class AgreementListRequest(APIRequestModel):
    filter: Optional[Union[Dict, AgreementListFilter]] = None
    last: Optional[str] = None
    order: Optional[ItemOrder] = None
    order_by: Optional[AgreementListOrderBy] = None
    size: Optional[int] = None


class AgreementListResult(PangeaResponseResult):
    agreements: List[AgreementInfo]
    count: int
    last: Optional[str] = None


class AgreementUpdateRequest(APIRequestModel):
    type: AgreementType
    id: str
    name: Optional[str] = None
    text: Optional[str] = None
    active: Optional[bool] = None


class AgreementUpdateResult(AgreementInfo):
    pass

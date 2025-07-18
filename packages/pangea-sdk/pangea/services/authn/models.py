# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from __future__ import annotations

import enum
from collections.abc import Mapping
from typing import Annotated, Literal, Optional, Union

from pydantic import Field

import pangea.services.intel as im
from pangea.response import APIRequestModel, APIResponseModel, PangeaDateTime, PangeaResponseResult
from pangea.services.vault.models.common import JWK, JWKec, JWKrsa

GroupId = Annotated[str, Field(pattern="^pgi_[a-z2-7]{32}$")]
Identity = Annotated[str, Field(pattern="^[a-zA-Z0-9 '.:/_-]+$")]
Scope = Annotated[str, Field(pattern="^[a-zA-Z0-9:*/_=-]+$")]
Token = Annotated[
    str, Field(pattern="^(p(ti|tr|ts|tu|cl)_[a-z2-7]{32})|([A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+)$")
]
TokenId = Annotated[str, Field(pattern="^pmt_[a-z2-7]{32}$")]
TokenType = Literal[
    "client", "service", "service_account", "service_account_client", "service_account_pangea", "session", "user"
]


class ClientPasswordChangeRequest(APIRequestModel):
    token: str
    old_password: str
    new_password: str


class ClientPasswordChangeResult(PangeaResponseResult):
    pass


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


class SessionToken(PangeaResponseResult):
    id: str
    type: str
    life: int
    expire: str
    identity: str
    email: str
    scopes: Optional[list[Scope]] = None
    profile: dict[str, str]
    created_at: str
    intelligence: Optional[Intelligence] = None


class LoginToken(SessionToken):
    token: str


class ClientTokenCheckResult(PangeaResponseResult):
    id: TokenId
    """An ID for a token"""

    type: TokenType
    """A token type"""

    life: Annotated[int, Field(gt=0)]
    """A positive time duration in seconds"""

    expire: PangeaDateTime
    """A time in ISO-8601 format"""

    enabled: Optional[bool] = None
    identity: Identity
    """The identity of a user or a service"""

    email: str
    scopes: Annotated[Optional[list[Scope]], Field(examples=[["scope1", "scope2"]])] = None
    """A list of scopes"""

    profile: Annotated[dict[str, str], Field(examples=[{"first_name": "Joe", "last_name": "User"}])]
    """A user profile as a collection of string properties"""

    created_at: PangeaDateTime
    """A time in ISO-8601 format"""

    intelligence: Optional[Intelligence] = None
    audience: Optional[list[str]] = None
    client_id: Annotated[
        Optional[str],
        Field(
            examples=["psa_wuk7tvtpswyjtlsx52b7yyi2l7zotv4a"],
            pattern="^psa_[a-z2-7]{32}$",
        ),
    ] = None
    """An ID for a service account"""

    claims: Optional[object] = None


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
    """Authenticator."""

    id: str
    """An ID for an authenticator."""

    type: str
    """An authentication mechanism."""

    enabled: bool
    """Enabled."""

    provider: Optional[str] = None
    """Provider."""

    provider_name: Optional[str] = None
    """Provider name."""

    rpid: Optional[str] = None
    """RPID."""

    phase: Optional[str] = None
    """Phase."""

    enrolling_browser: Optional[str] = None
    """Enrolling browser."""

    enrolling_ip: Optional[str] = None
    """Enrolling IP."""

    created_at: str
    """A time in ISO-8601 format."""

    updated_at: str
    """A time in ISO-8601 format."""

    state: Optional[str] = None
    """State."""


class User(PangeaResponseResult):
    id: str
    """The identity of a user or a service."""

    email: str
    """An email address."""

    username: str
    """A username."""

    profile: dict[str, str]
    """A user profile as a collection of string properties."""

    verified: bool
    """True if the user's email has been verified."""

    disabled: bool
    """True if the service administrator has disabled user account."""

    accepted_eula_id: Optional[str] = None
    """An ID for an agreement."""

    accepted_privacy_policy_id: Optional[str] = None
    """An ID for an agreement."""

    last_login_at: Optional[str] = None
    """A time in ISO-8601 format."""

    created_at: str
    """A time in ISO-8601 format."""

    login_count: int = 0
    last_login_ip: Optional[str] = None
    last_login_city: Optional[str] = None
    last_login_country: Optional[str] = None
    authenticators: list[Authenticator] = []
    """A list of authenticators."""


class UserCreateRequest(APIRequestModel):
    email: str
    """An email address."""

    profile: Mapping[str, str]
    """A user profile as a collection of string properties."""

    username: Optional[str] = None
    """A username."""


class UserCreateResult(User):
    pass


class UserDeleteRequest(APIRequestModel):
    email: Optional[str] = None
    """An email address."""

    id: Optional[str] = None
    """The identity of a user or a service."""

    username: Optional[str] = None
    """A username."""


class UserDeleteResult(PangeaResponseResult):
    pass


class UserListFilter(APIRequestModel):
    accepted_eula_id: Optional[str] = None
    accepted_eula_id__contains: Optional[list[str]] = None
    accepted_eula_id__in: Optional[list[str]] = None
    created_at: Optional[str] = None
    created_at__gt: Optional[str] = None
    created_at__gte: Optional[str] = None
    created_at__lt: Optional[str] = None
    created_at__lte: Optional[str] = None
    disabled: Optional[bool] = None
    email: Optional[str] = None
    email__contains: Optional[list[str]] = None
    email__in: Optional[list[str]] = None
    id: Optional[str] = None
    id__contains: Optional[list[str]] = None
    id__in: Optional[list[str]] = None
    last_login_at: Optional[str] = None
    last_login_at__gt: Optional[str] = None
    last_login_at__gte: Optional[str] = None
    last_login_at__lt: Optional[str] = None
    last_login_at__lte: Optional[str] = None
    last_login_ip: Optional[str] = None
    last_login_ip__contains: Optional[list[str]] = None
    last_login_ip__in: Optional[list[str]] = None
    last_login_city: Optional[str] = None
    last_login_city__contains: Optional[list[str]] = None
    last_login_city__in: Optional[list[str]] = None
    last_login_country: Optional[str] = None
    last_login_country__contains: Optional[list[str]] = None
    last_login_country__in: Optional[list[str]] = None
    login_count: Optional[int] = None
    login_count__gt: Optional[int] = None
    login_count__gte: Optional[int] = None
    login_count__lt: Optional[int] = None
    login_count__lte: Optional[int] = None
    require_mfa: Optional[bool] = None
    scopes: Optional[list[str]] = None
    verified: Optional[bool] = None


class UserListRequest(APIRequestModel):
    filter: Optional[UserListFilter] = None
    last: Optional[str] = None
    order: Optional[ItemOrder] = None
    order_by: Optional[UserListOrderBy] = None
    size: Optional[int] = None


class UserListResult(PangeaResponseResult):
    users: list[User]
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
    callback__contains: Optional[list[str]] = None
    callback__in: Optional[list[str]] = None
    created_at: Optional[str] = None
    created_at__gt: Optional[str] = None
    created_at__gte: Optional[str] = None
    created_at__lt: Optional[str] = None
    created_at__lte: Optional[str] = None
    email: Optional[str] = None
    email__contains: Optional[list[str]] = None
    email__in: Optional[list[str]] = None
    expire: Optional[str] = None
    expire__gt: Optional[str] = None
    expire__gte: Optional[str] = None
    expire__lt: Optional[str] = None
    expire__lte: Optional[str] = None
    id: Optional[str] = None
    id__contains: Optional[list[str]] = None
    id__in: Optional[list[str]] = None
    invite_org: Optional[str] = None
    invite_org__contains: Optional[list[str]] = None
    invite_org__in: Optional[list[str]] = None
    inviter: Optional[str] = None
    inviter__contains: Optional[list[str]] = None
    inviter__in: Optional[list[str]] = None
    is_signup: Optional[bool] = None
    require_mfa: Optional[bool] = None
    state: Optional[str] = None
    state__contains: Optional[list[str]] = None
    state__in: Optional[list[str]] = None


class UserInviteListRequest(APIRequestModel):
    filter: Optional[UserInviteListFilter] = None
    last: Optional[str] = None
    order: Optional[ItemOrder] = None
    order_by: Optional[UserInviterOrderBy] = None
    size: Optional[int] = None


class UserInviteListResult(PangeaResponseResult):
    invites: list[UserInvite]


class UserInviteDeleteRequest(APIRequestModel):
    id: str


class UserInviteDeleteResult(PangeaResponseResult):
    pass


class UserProfileGetRequest(APIRequestModel):
    id: Optional[str] = None
    """The identity of a user or a service."""

    email: Optional[str] = None
    """An email address."""

    username: Optional[str] = None
    """A username."""


class UserProfileGetResult(User):
    pass


class UserProfileUpdateRequest(APIRequestModel):
    profile: Mapping[str, str]
    """Updates to a user profile."""

    id: Optional[str] = None
    """The identity of a user or a service."""

    email: Optional[str] = None
    """An email address."""

    username: Optional[str] = None
    """A username."""


class UserProfileUpdateResult(User):
    pass


class UserUpdateRequest(APIRequestModel):
    id: Optional[str] = None
    """The identity of a user or a service."""

    email: Optional[str] = None
    """An email address."""

    disabled: Optional[bool] = None
    """
    New disabled value. Disabling a user account will prevent them from logging
    in.
    """

    unlock: Optional[bool] = None
    """
    Unlock a user account if it has been locked out due to failed authentication
    attempts.
    """

    username: Optional[str] = None
    """A username."""


class UserUpdateResult(User):
    pass


class ClientUserinfoResult(PangeaResponseResult):
    active_token: Optional[LoginToken] = None
    refresh_token: LoginToken


class ClientUserinfoRequest(APIRequestModel):
    code: str


class ClientJWKSResult(PangeaResponseResult):
    keys: list[Union[JWKec, JWKrsa, JWK]]


class UserAuthenticatorsDeleteRequest(APIRequestModel):
    id: Optional[str] = None
    """The identity of a user or a service."""

    email: Optional[str] = None
    """An email address."""

    authenticator_id: str
    """An ID for an authenticator."""

    username: Optional[str] = None
    """A username."""


class UserAuthenticatorsDeleteResult(PangeaResponseResult):
    pass


class UserAuthenticatorsListRequest(APIRequestModel):
    email: Optional[str] = None
    """An email address."""

    id: Optional[str] = None
    """The identity of a user or a service."""

    username: Optional[str] = None
    """A username."""


class UserAuthenticatorsListResult(PangeaResponseResult):
    authenticators: list[Authenticator] = []
    """A list of authenticators."""


class FlowCompleteRequest(APIRequestModel):
    flow_id: str


class FlowCompleteResult(PangeaResponseResult):
    refresh_token: LoginToken
    active_token: LoginToken


class FlowChoiceItem(APIResponseModel):
    choice: str
    data: dict = {}


class CommonFlowResult(PangeaResponseResult):
    flow_id: str
    flow_type: list[str] = []
    email: Optional[str] = None
    disclaimer: Optional[str] = None
    flow_phase: str
    flow_choices: list[FlowChoiceItem] = []


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


FlowRestartData = Union[dict, FlowRestartDataSMSOTP]


class FlowRestartRequest(APIRequestModel):
    flow_id: str
    choice: FlowChoice
    data: FlowRestartData


class FlowRestartResult(CommonFlowResult):
    pass


class FlowStartRequest(APIRequestModel):
    cb_uri: Optional[str] = None
    email: Optional[str] = None
    flow_types: Optional[list[FlowType]] = None
    invitation: Optional[str] = None


class FlowStartResult(CommonFlowResult):
    pass


class FlowUpdateDataAgreements(APIRequestModel):
    agreed: list[str]


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
    profile: dict[str, str]


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
    dict,
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
    active_token_id__contains: Optional[list[str]] = None
    active_token_id__in: Optional[list[str]] = None
    created_at: Optional[str] = None
    created_at__gt: Optional[str] = None
    created_at__gte: Optional[str] = None
    created_at__lt: Optional[str] = None
    created_at__lte: Optional[str] = None
    email: Optional[str] = None
    email__contains: Optional[list[str]] = None
    email__in: Optional[list[str]] = None
    expire: Optional[str] = None
    expire__gt: Optional[str] = None
    expire__gte: Optional[str] = None
    expire__lt: Optional[str] = None
    expire__lte: Optional[str] = None
    id: Optional[str] = None
    id__contains: Optional[list[str]] = None
    id__in: Optional[list[str]] = None
    identity: Optional[str] = None
    identity__contains: Optional[list[str]] = None
    identity__in: Optional[list[str]] = None
    scopes: Optional[list[str]] = None
    type: Optional[str] = None
    type__contains: Optional[list[str]] = None
    type__in: Optional[list[str]] = None


class ClientSessionListRequest(APIRequestModel):
    token: str
    filter: Optional[SessionListFilter] = None
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
    scopes: Optional[list[Scope]] = None
    profile: dict[str, str]
    created_at: str
    active_token: Optional[SessionToken] = None


class ClientSessionListResults(PangeaResponseResult):
    sessions: list[SessionItem]
    last: str


class SessionListResults(PangeaResponseResult):
    sessions: list[SessionItem]
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
    filter: Optional[SessionListFilter] = None
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
    """Only records where active equals this value."""
    created_at: Optional[PangeaDateTime] = None
    """Only records where created_at equals this value."""
    created_at__gt: Optional[PangeaDateTime] = None
    """Only records where created_at is greater than this value."""
    created_at__gte: Optional[PangeaDateTime] = None
    """Only records where created_at is greater than or equal to this value."""
    created_at__lt: Optional[PangeaDateTime] = None
    """Only records where created_at is less than this value."""
    created_at__lte: Optional[PangeaDateTime] = None
    """Only records where created_at is less than or equal to this value."""
    id: Optional[str] = None
    """Only records where id equals this value."""
    id__contains: Optional[list[str]] = None
    """Only records where id includes each substring."""
    id__in: Optional[list[str]] = None
    """Only records where id equals one of the provided substrings."""
    name: Optional[str] = None
    """Only records where name equals this value."""
    name__contains: Optional[list[str]] = None
    """Only records where name includes each substring."""
    name__in: Optional[list[str]] = None
    """Only records where name equals one of the provided substrings."""
    published_at: Optional[PangeaDateTime] = None
    """Only records where published_at equals this value."""
    published_at__gt: Optional[PangeaDateTime] = None
    """Only records where published_at is greater than this value."""
    published_at__gte: Optional[PangeaDateTime] = None
    """Only records where published_at is greater than or equal to this value."""
    published_at__lt: Optional[PangeaDateTime] = None
    """Only records where published_at is less than this value."""
    published_at__lte: Optional[PangeaDateTime] = None
    """Only records where published_at is less than or equal to this value."""
    text: Optional[str] = None
    """Only records where text equals this value."""
    text__contains: Optional[list[str]] = None
    """Only records where text includes each substring."""
    text__in: Optional[list[str]] = None
    """Only records where text equals one of the provided substrings."""
    type: Optional[str] = None
    """Only records where type equals this value."""
    type__contains: Optional[list[str]] = None
    """Only records where type includes each substring."""
    type__in: Optional[list[str]] = None
    """Only records where type equals one of the provided substrings."""
    updated_at: Optional[PangeaDateTime] = None
    """Only records where updated_at equals this value."""
    updated_at__gt: Optional[PangeaDateTime] = None
    """Only records where updated_at is greater than this value."""
    updated_at__gte: Optional[PangeaDateTime] = None
    """Only records where updated_at is greater than or equal to this value."""
    updated_at__lt: Optional[PangeaDateTime] = None
    """Only records where updated_at is less than this value."""
    updated_at__lte: Optional[PangeaDateTime] = None
    """Only records where updated_at is less than or equal to this value."""


class AgreementListRequest(APIRequestModel):
    filter: Optional[AgreementListFilter] = None
    last: Optional[str] = None
    order: Optional[ItemOrder] = None
    order_by: Optional[AgreementListOrderBy] = None
    size: Optional[int] = None


class AgreementListResult(PangeaResponseResult):
    agreements: list[AgreementInfo]
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


class GroupInfo(PangeaResponseResult):
    """A group and its information"""

    id: GroupId
    """An ID for a group"""

    name: str
    type: str

    description: Optional[str] = None
    attributes: Optional[dict[str, str]] = None
    """A collection of key/value pairs"""

    created_at: Optional[PangeaDateTime] = None
    """A time in ISO-8601 format"""

    updated_at: Optional[PangeaDateTime] = None
    """A time in ISO-8601 format"""


class GroupsFilter(APIRequestModel):
    """Search filter for groups"""

    created_at: Optional[str] = None
    """Only records where created_at equals this value."""

    created_at__gt: Optional[str] = None
    """Only records where created_at is greater than this value."""

    created_at__gte: Optional[str] = None
    """Only records where created_at is greater than or equal to this value."""

    created_at__lt: Optional[str] = None
    """Only records where created_at is less than this value."""

    created_at__lte: Optional[str] = None
    """Only records where created_at is less than or equal to this value."""

    created_at__contains: Optional[str] = None
    """Only records where created_at includes this value."""

    id: Optional[str] = None
    """Only records where id equals this value."""

    id__contains: Optional[list[str]] = None
    """Only records where id includes each substring."""

    id__in: Optional[list[str]] = None
    """Only records where id equals one of the provided substrings."""

    name: Optional[str] = None
    """Only records where name equals this value."""

    name__contains: Optional[list[str]] = None
    """Only records where name includes each substring."""

    name__in: Optional[list[str]] = None
    """Only records where name equals one of the provided substrings."""

    type: Optional[str] = None
    """Only records where type equals this value."""

    type__contains: Optional[list[str]] = None
    """Only records where type includes each substring."""

    type__in: Optional[list[str]] = None
    """Only records where type equals one of the provided substrings."""

    updated_at: Optional[str] = None
    """Only records where updated_at equals this value."""

    updated_at__gt: Optional[str] = None
    """Only records where updated_at is greater than this value."""

    updated_at__gte: Optional[str] = None
    """Only records where updated_at is greater than or equal to this value."""

    updated_at__lt: Optional[str] = None
    """Only records where updated_at is less than this value."""

    updated_at__lte: Optional[str] = None
    """Only records where updated_at is less than or equal to this value."""

    updated_at__contains: Optional[str] = None
    """Only records where updated_at includes this value."""


class GroupList(PangeaResponseResult):
    groups: list[GroupInfo]
    """List of matching groups"""

    count: int
    last: Optional[str] = None


class GroupUserList(PangeaResponseResult):
    users: list[User]
    count: int
    last: Optional[str] = None

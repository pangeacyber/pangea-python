# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from typing import Dict, List, Optional

import pangea.services.authn.models as m
from pangea.response import PangeaResponse
from pangea.services.base import ServiceBase

SERVICE_NAME = "authn"
VERSION = "v1"


class AuthN(ServiceBase):
    """AuthN service client.

    Provides methods to interact with the [Pangea AuthN Service](https://pangea.cloud/docs/api/authn).

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import AuthN

        PANGEA_TOKEN = os.getenv("PANGEA_AUTHN_TOKEN")
        authn_config = PangeaConfig(domain="pangea.cloud")

        # Setup Pangea AuthN service
        authn = AuthN(token=PANGEA_TOKEN, config=authn_config)
    """

    service_name: str = SERVICE_NAME
    version: str = VERSION

    def __init__(
        self,
        token,
        config=None,
        logger_name="pangea",
    ):
        super().__init__(token, config, logger_name=logger_name)
        self.user = AuthN.User(token, config, logger_name=logger_name)
        self.flow = AuthN.Flow(token, config, logger_name=logger_name)
        self.client = AuthN.Client(token, config, logger_name=logger_name)
        self.session = AuthN.Session(token, config, logger_name=logger_name)

    class Session(ServiceBase):
        service_name: str = SERVICE_NAME
        version: str = VERSION

        def __init__(
            self,
            token,
            config=None,
            logger_name="pangea",
        ):
            super().__init__(token, config, logger_name=logger_name)

        # https://dev.pangea.cloud/docs/api/authn#invalidate-a-session-by-session-id
        # - path: authn::/v1/session/invalidate
        def invalidate(self, session_id: str) -> PangeaResponse[m.SessionInvalidateResult]:
            input = m.SessionInvalidateRequest(session_id=session_id)
            return self.request.post(
                "session/invalidate", m.SessionInvalidateResult, data=input.dict(exclude_none=True)
            )

        # https://dev.pangea.cloud/docs/api/authn#list-sessions
        # - path: authn::/v1/session/list
        def list(
            self,
            filter: Optional[Dict] = None,
            last: Optional[str] = None,
            order: Optional[m.ItemOrder] = None,
            order_by: Optional[m.SessionListOrderBy] = None,
            size: Optional[int] = None,
        ) -> PangeaResponse[m.SessionListResults]:
            input = m.SessionListRequest(filter=filter, last=last, order=order, order_by=order_by, size=size)
            return self.request.post("session/list", m.SessionListResults, data=input.dict(exclude_none=True))

        # https://dev.pangea.cloud/docs/api/authn#invalidate-all-sessions-belonging-to-a-user
        # - path: authn::/v1/session/logout
        def logout(self, user_id: str) -> PangeaResponse[m.SessionLogoutResult]:
            input = m.SessionLogoutRequest(user_id=user_id)
            return self.request.post("session/logout", m.SessionLogoutResult, data=input.dict(exclude_none=True))

    class Client(ServiceBase):
        service_name: str = SERVICE_NAME
        version: str = VERSION

        def __init__(
            self,
            token,
            config=None,
            logger_name="pangea",
        ):
            super().__init__(token, config, logger_name=logger_name)
            self.session = AuthN.Client.Session(token, config, logger_name=logger_name)
            self.password = AuthN.Client.Password(token, config, logger_name=logger_name)

        # https://dev.pangea.cloud/docs/api/authn#complete-a-login
        def userinfo(self, code: str) -> PangeaResponse[m.ClientUserinfoResult]:
            input = m.ClientUserinfoRequest(code=code)
            return self.request.post("client/userinfo", m.ClientUserinfoResult, data=input.dict(exclude_none=True))

        def jwks(
            self,
        ) -> PangeaResponse[m.ClientJWKSResult]:
            return self.request.post("client/jwks", m.ClientJWKSResult, {})

        class Session(ServiceBase):
            service_name: str = SERVICE_NAME
            version: str = VERSION

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            # - path: authn::/v1/client/session/invalidate
            # https://dev.pangea.cloud/docs/api/authn?focus=authn#invalidate-a-session-by-session-id-using-a-client-token
            def invalidate(self, token: str, session_id: str) -> PangeaResponse[m.ClientSessionInvalidateResult]:
                input = m.ClientSessionInvalidateRequest(token=token, session_id=session_id)
                return self.request.post(
                    "client/session/invalidate", m.ClientSessionInvalidateResult, data=input.dict(exclude_none=True)
                )

            # https://dev.pangea.cloud/docs/api/authn#list-sessions-using-a-client-token
            # - path: authn::/v1/client/session/list
            def list(
                self,
                token: str,
                filter: Optional[Dict] = None,
                last: Optional[str] = None,
                order: Optional[m.ItemOrder] = None,
                order_by: Optional[m.SessionListOrderBy] = None,
                size: Optional[int] = None,
            ) -> PangeaResponse[m.ClientSessionListResults]:
                input = m.ClientSessionInvalidateRequest(
                    token=token, filter=filter, last=last, order=order, order_by=order_by, size=size
                )
                return self.request.post(
                    "client/session/list", m.ClientSessionListResults, data=input.dict(exclude_none=True)
                )

            # https://dev.pangea.cloud/docs/api/authn#log-out-the-current-users-session
            # - path: authn::/v1/client/session/logout
            def logout(self, token: str) -> PangeaResponse[m.ClientSessionLogoutResult]:
                input = m.ClientSessionLogoutRequest(token=token)
                return self.request.post(
                    "client/session/logout", m.ClientSessionLogoutResult, data=input.dict(exclude_none=True)
                )

            # https://dev.pangea.cloud/docs/api/authn#refresh-a-session-token
            # - path: authn::/v1/client/session/refresh
            def refresh(
                self, refresh_token: str, user_token: Optional[str] = None
            ) -> PangeaResponse[m.ClientSessionRefreshResult]:
                input = m.ClientSessionRefreshRequest(refresh_token=refresh_token, user_token=user_token)
                return self.request.post(
                    "client/session/refresh", m.ClientSessionRefreshResult, data=input.dict(exclude_none=True)
                )

        class Password(ServiceBase):
            service_name: str = SERVICE_NAME
            version: str = VERSION

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            # https://dev.pangea.cloud/docs/api/authn#change-a-users-password
            def change(
                self, token: str, old_password: str, new_password: str
            ) -> PangeaResponse[m.ClientPasswordChangeResult]:
                input = m.ClientPasswordChangeRequest(token=token, old_password=old_password, new_password=new_password)
                return self.request.post(
                    "client/password/change", m.ClientPasswordChangeResult, data=input.dict(exclude_none=True)
                )

        class Token(ServiceBase):
            service_name: str = SERVICE_NAME
            version: str = VERSION

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

        def check(self, token: str) -> PangeaResponse[m.ClientTokenCheckResult]:
            input = m.ClientTokenCheckRequest(token=token)
            return self.request.post("client/token/check", m.ClientTokenCheckResult, data=input.dict(exclude_none=True))

    class User(ServiceBase):
        service_name: str = SERVICE_NAME
        version: str = VERSION

        def __init__(
            self,
            token,
            config=None,
            logger_name="pangea",
        ):
            super().__init__(token, config, logger_name=logger_name)
            self.profile = AuthN.User.Profile(token, config, logger_name=logger_name)
            self.invites = AuthN.User.Invites(token, config, logger_name=logger_name)
            self.mfa = AuthN.User.MFA(token, config, logger_name=logger_name)
            self.login = AuthN.User.Login(token, config, logger_name=logger_name)

        #   - path: authn::/v1/user/create
        # https://dev.pangea.cloud/docs/api/authn#create-user
        def create(
            self,
            email: str,
            authenticator: str,
            id_provider: m.IDProvider,
            verified: Optional[bool] = None,
            require_mfa: Optional[bool] = None,
            profile: Optional[m.Profile] = None,
            scopes: Optional[m.Scopes] = None,
        ) -> PangeaResponse[m.UserCreateResult]:

            input = m.UserCreateRequest(
                email=email,
                authenticator=authenticator,
                id_provider=id_provider,
                verified=verified,
                require_mfa=require_mfa,
                profile=profile,
                scopes=scopes,
            )
            return self.request.post("user/create", m.UserCreateResult, data=input.dict(exclude_none=True))

        #   - path: authn::/v1/user/delete
        # https://dev.pangea.cloud/docs/api/authn#delete-a-user
        def delete(self, email: Optional[str] = None, id: Optional[str] = None) -> PangeaResponse[m.UserDeleteResult]:
            input = m.UserDeleteRequest(email=email, id=id)
            return self.request.post("user/delete", m.UserDeleteResult, data=input.dict(exclude_none=True))

        # https://dev.pangea.cloud/docs/api/authn/#administration-user-update
        def update(
            self,
            id: Optional[str] = None,
            email: Optional[str] = None,
            authenticator: Optional[str] = None,
            disabled: Optional[bool] = None,
            require_mfa: Optional[bool] = None,
            verified: Optional[bool] = None,
        ) -> PangeaResponse[m.UserUpdateResult]:
            input = m.UserUpdateRequest(
                id=id,
                email=email,
                authenticator=authenticator,
                disabled=disabled,
                require_mfa=require_mfa,
                verified=verified,
            )

            return self.request.post("user/update", m.UserUpdateResult, data=input.dict(exclude_none=True))

        #   - path: authn::/v1/user/invite
        # https://dev.pangea.cloud/docs/api/authn#invite-a-user
        def invite(
            self,
            inviter: str,
            email: str,
            callback: str,
            state: str,
            require_mfa: Optional[bool] = None,
        ) -> PangeaResponse[m.UserInviteResult]:
            input = m.UserInviteRequest(
                inviter=inviter,
                email=email,
                callback=callback,
                state=state,
                require_mfa=require_mfa,
            )
            return self.request.post("user/invite", m.UserInviteResult, data=input.dict(exclude_none=True))

        #   - path: authn::/v1/user/list
        # https://dev.pangea.cloud/docs/api/authn#list-users
        def list(
            self,
            filter: Optional[Dict] = None,
            last: Optional[str] = None,
            order: Optional[m.ItemOrder] = None,
            order_by: Optional[m.UserListOrderBy] = None,
            size: Optional[int] = None,
        ) -> PangeaResponse[m.UserListResult]:
            input = m.UserListRequest(
                filter=filter,
                last=last,
                order=order,
                order_by=order_by,
                size=size,
            )
            return self.request.post("user/list", m.UserListResult, data=input.dict(exclude_none=True))

        #   - path: authn::/v1/user/verify
        # https://dev.pangea.cloud/docs/api/authn#verify-a-user
        def verify(
            self, id_provider: m.IDProvider, email: str, authenticator: str
        ) -> PangeaResponse[m.UserVerifyResult]:
            input = m.UserVerifyRequest(id_provider=id_provider, email=email, authenticator=authenticator)
            return self.request.post("user/verify", m.UserVerifyResult, data=input.dict(exclude_none=True))

        class Password(ServiceBase):
            service_name: str = SERVICE_NAME
            version: str = VERSION

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            #   - path: authn::/v1/password/update
            # https://dev.pangea.cloud/docs/api/authn#change-a-users-password
            def reset(self, user_id: str, new_password: str) -> PangeaResponse[m.UserPasswordResetResult]:
                input = m.UserPasswordResetRequest(user_id=user_id, new_password=new_password)
                return self.request.post(
                    "user/password/reset", m.UserPasswordResetResult, data=input.dict(exclude_none=True)
                )

        class Login(ServiceBase):
            service_name: str = SERVICE_NAME
            version: str = VERSION

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            # https://dev.pangea.cloud/docs/api/authn#user-login-with-a-password
            def password(
                self, email: str, password: str, extra_profile: Optional[m.Profile] = None
            ) -> PangeaResponse[m.UserLoginResult]:
                input = m.UserLoginPasswordRequest(email=email, password=password, extra_profile=extra_profile)
                return self.request.post("user/login/password", m.UserLoginResult, data=input.dict(exclude_none=True))

            # https://dev.pangea.cloud/docs/api/authn#user-login-with-a-social-provider
            def social(
                self, provider: m.IDProvider, email: str, social_id: str, extra_profile: Optional[m.Profile] = None
            ) -> PangeaResponse[m.UserLoginResult]:
                input = m.UserLoginSocialRequest(
                    provider=provider, email=email, social_id=social_id, extra_profile=extra_profile
                )
                return self.request.post("user/login/social", m.UserLoginResult, data=input.dict(exclude_none=True))

        class MFA(ServiceBase):
            service_name: str = SERVICE_NAME
            version: str = VERSION

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            #   - path: authn::/v1/user/mfa/delete
            # https://dev.pangea.cloud/docs/api/authn#delete-mfa-enrollment-for-a-user
            def delete(self, user_id: str, mfa_provider: m.MFAProvider) -> PangeaResponse[m.UserMFADeleteResult]:
                input = m.UserMFADeleteRequest(user_id=user_id, mfa_provider=mfa_provider)
                return self.request.post("user/mfa/delete", m.UserMFADeleteResult, data=input.dict(exclude_none=True))

            #   - path: authn::/v1/user/mfa/enroll
            # https://dev.pangea.cloud/docs/api/authn#enroll-mfa-for-a-user
            def enroll(
                self, user_id: str, mfa_provider: m.MFAProvider, code: str
            ) -> PangeaResponse[m.UserMFAEnrollResult]:
                input = m.UserMFAEnrollRequest(user_id=user_id, mfa_provider=mfa_provider, code=code)
                return self.request.post("user/mfa/enroll", m.UserMFAEnrollResult, data=input.dict(exclude_none=True))

            #   - path: authn::/v1/user/mfa/start
            # https://dev.pangea.cloud/docs/api/authn#start-mfa-verification-for-a-user
            def start(
                self,
                user_id: str,
                mfa_provider: m.MFAProvider,
                enroll: Optional[bool] = None,
                phone: Optional[str] = None,
            ) -> PangeaResponse[m.UserMFAStartResult]:
                input = m.UserMFAStartRequest(user_id=user_id, mfa_provider=mfa_provider, enroll=enroll, phone=phone)
                return self.request.post("user/mfa/start", m.UserMFAStartResult, data=input.dict(exclude_none=True))

            #   - path: authn::/v1/user/mfa/verify
            # https://dev.pangea.cloud/docs/api/authn#verify-an-mfa-code
            def verify(
                self, user_id: str, mfa_provider: m.MFAProvider, code: str
            ) -> PangeaResponse[m.UserMFAVerifyResult]:
                input = m.UserMFAverifyRequest(user_id=user_id, mfa_provider=mfa_provider, code=code)
                return self.request.post("user/mfa/verify", m.UserMFAVerifyResult, data=input.dict(exclude_none=True))

        class Profile(ServiceBase):
            service_name: str = SERVICE_NAME
            version: str = VERSION

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            #   - path: authn::/v1/user/profile/get
            # https://dev.pangea.cloud/docs/api/authn#get-user
            def get(
                self, id: Optional[str] = None, email: Optional[str] = None
            ) -> PangeaResponse[m.UserProfileGetResult]:
                input = m.UserProfileGetRequest(id=id, email=email)
                return self.request.post("user/profile/get", m.UserProfileGetResult, data=input.dict(exclude_none=True))

            #   - path: authn::/v1/user/profile/update
            # https://dev.pangea.cloud/docs/api/authn#update-user
            def update(
                self,
                profile: m.Profile,
                id: Optional[str] = None,
                email: Optional[str] = None,
            ) -> PangeaResponse[m.UserProfileUpdateResult]:
                input = m.UserProfileUpdateRequest(
                    id=id,
                    email=email,
                    profile=profile,
                )
                return self.request.post(
                    "user/profile/update", m.UserProfileUpdateResult, data=input.dict(exclude_none=True)
                )

        class Invites(ServiceBase):
            service_name: str = SERVICE_NAME
            version: str = VERSION

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            #   - path: authn::/v1/user/invite/list
            # https://dev.pangea.cloud/docs/api/authn#list-invites
            def list(
                self,
                filter: Optional[Dict] = None,
                last: Optional[str] = None,
                order: Optional[m.ItemOrder] = None,
                order_by: Optional[m.UserInviterOrderBy] = None,
                size: Optional[int] = None,
            ) -> PangeaResponse[m.UserInviteListResult]:
                input = m.UserInviteListRequest(filter=filter, last=last, order=order, order_by=order_by, size=size)
                return self.request.post("user/invite/list", m.UserInviteListResult, data=input.dict(exclude_none=True))

            #   - path: authn::/v1/user/invite/delete
            # https://dev.pangea.cloud/docs/api/authn#delete-an-invite
            def delete(self, id: str) -> PangeaResponse[m.UserInviteDeleteResult]:
                input = m.UserInviteDeleteRequest(id=id)
                return self.request.post(
                    "user/invite/delete", m.UserInviteDeleteResult, data=input.dict(exclude_none=True)
                )

    class Flow(ServiceBase):
        service_name: str = SERVICE_NAME
        version: str = VERSION

        def __init__(
            self,
            token,
            config=None,
            logger_name="pangea",
        ):
            super().__init__(token, config, logger_name=logger_name)
            self.enroll = AuthN.Flow.Enroll(token, config, logger_name=logger_name)
            self.signup = AuthN.Flow.Signup(token, config, logger_name=logger_name)
            self.verify = AuthN.Flow.Verify(token, config, logger_name=logger_name)
            self.reset = AuthN.Flow.Reset(token, config, logger_name=logger_name)

        #   - path: authn::/v1/flow/complete
        # https://dev.pangea.cloud/docs/api/authn#complete-a-login-or-signup-flow
        def complete(self, flow_id: str) -> PangeaResponse[m.FlowCompleteResult]:
            input = m.FlowCompleteRequest(flow_id=flow_id)
            return self.request.post("flow/complete", m.FlowCompleteResult, data=input.dict(exclude_none=True))

        #   - path: authn::/v1/flow/start
        # https://dev.pangea.cloud/docs/api/authn#start-a-new-signup-or-signin-flow
        def start(
            self,
            cb_uri: Optional[str] = None,
            email: Optional[str] = None,
            flow_types: Optional[List[m.FlowType]] = None,
            provider: Optional[m.MFAProvider] = None,
        ) -> PangeaResponse[m.FlowStartResult]:
            input = m.FlowStartRequest(cb_uri=cb_uri, email=email, flow_types=flow_types, provider=provider)
            return self.request.post("flow/start", m.FlowStartResult, data=input.dict(exclude_none=True))

        class Reset(ServiceBase):
            service_name: str = SERVICE_NAME
            version: str = VERSION

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            #   - path: authn::/v1/flow/reset/password
            # https://dev.pangea.cloud/docs/api/authn#reset-password-during-signin
            def password(
                self,
                flow_id: str,
                password: str,
                cancel: Optional[bool] = None,
                cb_state: Optional[str] = None,
                cb_code: Optional[str] = None,
            ) -> PangeaResponse[m.FlowResetPasswordResult]:
                input = m.FlowResetPasswordRequest(
                    flow_id=flow_id, password=password, cb_state=cb_state, cb_code=cb_code, cancel=cancel
                )
                return self.request.post(
                    "flow/reset/password", m.FlowResetPasswordResult, data=input.dict(exclude_none=True)
                )

        class Enroll(ServiceBase):
            service_name: str = SERVICE_NAME
            version: str = VERSION

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)
                self.mfa = AuthN.Flow.Enroll.MFA(token, config, logger_name=logger_name)

            class MFA(ServiceBase):
                service_name: str = SERVICE_NAME
                version: str = VERSION

                def __init__(
                    self,
                    token,
                    config=None,
                    logger_name="pangea",
                ):
                    super().__init__(token, config, logger_name=logger_name)

                #   - path: authn::/v1/flow/enroll/mfa/complete
                # https://dev.pangea.cloud/docs/api/authn#complete-mfa-enrollment-by-verifying-a-trial-mfa-code
                def complete(
                    self, flow_id: str, code: Optional[str] = None, cancel: Optional[bool] = None
                ) -> PangeaResponse[m.FlowEnrollMFAcompleteResult]:
                    input = m.FlowEnrollMFACompleteRequest(flow_id=flow_id, code=code, cancel=cancel)
                    return self.request.post(
                        "flow/enroll/mfa/complete", m.FlowEnrollMFAcompleteResult, data=input.dict(exclude_none=True)
                    )

                #   - path: authn::/v1/flow/enroll/mfa/start
                # https://dev.pangea.cloud/docs/api/authn#start-the-process-of-enrolling-an-mfa
                def start(
                    self, flow_id: str, mfa_provider: m.MFAProvider, phone: Optional[str] = None
                ) -> PangeaResponse[m.FlowEnrollMFAStartResult]:
                    input = m.FlowEnrollMFAStartRequest(flow_id=flow_id, mfa_provider=mfa_provider, phone=phone)
                    return self.request.post(
                        "flow/enroll/mfa/start", m.FlowEnrollMFAStartResult, data=input.dict(exclude_none=True)
                    )

        class Signup(ServiceBase):
            service_name: str = SERVICE_NAME
            version: str = VERSION

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            #   - path: authn::/v1/flow/signup/password
            # https://dev.pangea.cloud/docs/api/authn#signup-a-new-account-using-a-password
            def password(
                self, flow_id: str, password: str, first_name: str, last_name: str
            ) -> PangeaResponse[m.FlowSignupPasswordResult]:
                input = m.FlowSignupPasswordRequest(
                    flow_id=flow_id, password=password, first_name=first_name, last_name=last_name
                )
                return self.request.post(
                    "flow/signup/password", m.FlowSignupPasswordResult, data=input.dict(exclude_none=True)
                )

            #   - path: authn::/v1/flow/signup/social
            # https://dev.pangea.cloud/docs/api/authn#signup-a-new-account-using-a-social-provider
            def social(self, flow_id: str, cb_state: str, cb_code: str) -> PangeaResponse[m.FlowSignupSocialResult]:
                input = m.FlowSignupSocialRequest(flow_id=flow_id, cb_state=cb_state, cb_code=cb_code)
                return self.request.post(
                    "flow/signup/social", m.FlowSignupSocialResult, data=input.dict(exclude_none=True)
                )

        class Verify(ServiceBase):
            service_name: str = SERVICE_NAME
            version: str = VERSION

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)
                self.mfa = AuthN.Flow.Verify.MFA(token, config, logger_name=logger_name)

            #   - path: authn::/v1/flow/verify/captcha
            # https://dev.pangea.cloud/docs/api/authn#verify-a-captcha-during-a-signup-or-signin-flow
            def captcha(self, flow_id: str, code: str) -> PangeaResponse[m.FlowVerifyCaptchaResult]:
                input = m.FlowVerifyCaptchaRequest(flow_id=flow_id, code=code)
                return self.request.post(
                    "flow/verify/captcha", m.FlowVerifyCaptchaResult, data=input.dict(exclude_none=True)
                )

            #   - path: authn::/v1/flow/verify/email
            # https://dev.pangea.cloud/docs/api/authn#verify-an-email-address-during-a-signup-or-signin-flow
            def email(
                self, flow_id: str, cb_state: Optional[str] = None, cb_code: Optional[str] = None
            ) -> PangeaResponse[m.FlowVerifyEmailResult]:
                input = m.FlowVerifyEmailRequest(flow_id=flow_id, cb_state=cb_state, cb_code=cb_code)
                return self.request.post(
                    "flow/verify/email", m.FlowVerifyEmailResult, data=input.dict(exclude_none=True)
                )

            #   - path: authn::/v1/flow/verify/password
            # https://dev.pangea.cloud/docs/api/authn#sign-in-with-a-password
            def password(
                self, flow_id: str, password: Optional[str] = None, cancel: Optional[bool] = None
            ) -> PangeaResponse[m.FlowVerifyPasswordResult]:
                input = m.FlowVerifyPasswordRequest(flow_id=flow_id, password=password, cancel=cancel)
                return self.request.post(
                    "flow/verify/password", m.FlowVerifyPasswordResult, data=input.dict(exclude_none=True)
                )

            #   - path: authn::/v1/flow/verify/social
            # https://dev.pangea.cloud/docs/api/authn#signin-with-a-social-provider
            def social(self, flow_id: str, cb_state: str, cb_code: str) -> PangeaResponse[m.FlowVerifySocialResult]:
                input = m.FlowVerifySocialRequest(flow_id=flow_id, cb_state=cb_state, cb_code=cb_code)
                return self.request.post(
                    "flow/verify/social", m.FlowVerifySocialResult, data=input.dict(exclude_none=True)
                )

            class MFA(ServiceBase):
                service_name: str = SERVICE_NAME
                version: str = VERSION

                def __init__(
                    self,
                    token,
                    config=None,
                    logger_name="pangea",
                ):
                    super().__init__(token, config, logger_name=logger_name)

                #   - path: authn::/v1/flow/verify/mfa/complete
                # https://dev.pangea.cloud/docs/api/authn#complete-mfa-verification
                def complete(
                    self, flow_id: str, code: Optional[str] = None, cancel: Optional[bool] = None
                ) -> PangeaResponse[m.FlowVerifyMFACompleteResult]:
                    input = m.FlowVerifyMFACompleteRequest(flow_id=flow_id, code=code, cancel=cancel)
                    return self.request.post(
                        "flow/verify/mfa/complete", m.FlowVerifyMFACompleteResult, data=input.dict(exclude_none=True)
                    )

                #   - path: authn::/v1/flow/verify/mfa/start
                # https://dev.pangea.cloud/docs/api/authn#start-the-process-of-mfa-verification
                def start(
                    self, flow_id: str, mfa_provider: m.MFAProvider
                ) -> PangeaResponse[m.FlowVerifyMFAStartResult]:
                    input = m.FlowVerifyMFAStartRequest(flow_id=flow_id, mfa_provider=mfa_provider)
                    return self.request.post(
                        "flow/verify/mfa/start", m.FlowVerifyMFAStartResult, data=input.dict(exclude_none=True)
                    )

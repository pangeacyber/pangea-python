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
            response = self.request.post("session/invalidate", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.SessionInvalidateResult(**response.raw_result)
            return response

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
            response = self.request.post("session/list", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.SessionListResults(**response.raw_result)
            return response

        # https://dev.pangea.cloud/docs/api/authn#invalidate-all-sessions-belonging-to-a-user
        # - path: authn::/v1/session/logout
        def logout(self, user_id: str) -> PangeaResponse[m.SessionLogoutResult]:
            input = m.SessionLogoutRequest(user_id=user_id)
            response = self.request.post("session/logout", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.SessionLogoutResult(**response.raw_result)
            return response

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
            response = self.request.post("client/userinfo", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.ClientUserinfoResult(**response.raw_result)
            return response

        def jwks(
            self,
        ) -> PangeaResponse[m.ClientJWKSResult]:
            response = self.request.post("client/jwks", {})
            if response.raw_result is not None:
                response.result = m.ClientJWKSResult(**response.raw_result)
            return response

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
                response = self.request.post("client/session/invalidate", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.ClientSessionInvalidateResult(**response.raw_result)
                return response

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
                response = self.request.post("client/session/list", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.ClientSessionListResults(**response.raw_result)
                return response

            # https://dev.pangea.cloud/docs/api/authn#log-out-the-current-users-session
            # - path: authn::/v1/client/session/logout
            def logout(self, token: str) -> PangeaResponse[m.ClientSessionLogoutResult]:
                input = m.ClientSessionLogoutRequest(token=token)
                response = self.request.post("client/session/logout", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.ClientSessionLogoutResult(**response.raw_result)
                return response

            # https://dev.pangea.cloud/docs/api/authn#refresh-a-session-token
            # - path: authn::/v1/client/session/refresh
            def refresh(
                self, refresh_token: str, user_token: Optional[str] = None
            ) -> PangeaResponse[m.ClientSessionRefreshResult]:
                input = m.ClientSessionRefreshRequest(refresh_token=refresh_token, user_token=user_token)
                response = self.request.post("client/session/refresh", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.ClientSessionRefreshResult(**response.raw_result)
                return response

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
                response = self.request.post("client/password/change", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.ClientPasswordChangeResult(**response.raw_result)
                return response

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
            response = self.request.post("client/token/check", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.ClientTokenCheckResult(**response.raw_result)
            return response

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
            response = self.request.post("user/create", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.UserCreateResult(**response.raw_result)
            return response

        #   - path: authn::/v1/user/delete
        # https://dev.pangea.cloud/docs/api/authn#delete-a-user
        def delete(self, email: Optional[str] = None, id: Optional[str] = None) -> PangeaResponse[m.UserDeleteResult]:
            input = m.UserDeleteRequest(email=email, id=id)
            response = self.request.post("user/delete", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.UserDeleteResult(**response.raw_result)
            return response

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

            response = self.request.post("user/update", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.UserUpdateResult(**response.raw_result)
            return response

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
            response = self.request.post("user/invite", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.UserInviteResult(**response.raw_result)
            return response

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
            response = self.request.post("user/list", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.UserListResult(**response.raw_result)
            return response

        #   - path: authn::/v1/user/verify
        # https://dev.pangea.cloud/docs/api/authn#verify-a-user
        def verify(
            self, id_provider: m.IDProvider, email: str, authenticator: str
        ) -> PangeaResponse[m.UserVerifyResult]:
            input = m.UserVerifyRequest(id_provider=id_provider, email=email, authenticator=authenticator)
            response = self.request.post("user/verify", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.UserVerifyResult(**response.raw_result)
            return response

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
                response = self.request.post("user/password/reset", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserPasswordResetResult(**response.raw_result)
                return response

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
                response = self.request.post("user/login/password", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserLoginResult(**response.raw_result)
                return response

            # https://dev.pangea.cloud/docs/api/authn#user-login-with-a-social-provider
            def social(
                self, provider: m.IDProvider, email: str, social_id: str, extra_profile: Optional[m.Profile] = None
            ) -> PangeaResponse[m.UserLoginResult]:
                input = m.UserLoginSocialRequest(
                    provider=provider, email=email, social_id=social_id, extra_profile=extra_profile
                )
                response = self.request.post("user/login/social", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserLoginResult(**response.raw_result)
                return response

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
                response = self.request.post("user/mfa/delete", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserMFADeleteResult(**response.raw_result)
                return response

            #   - path: authn::/v1/user/mfa/enroll
            # https://dev.pangea.cloud/docs/api/authn#enroll-mfa-for-a-user
            def enroll(
                self, user_id: str, mfa_provider: m.MFAProvider, code: str
            ) -> PangeaResponse[m.UserMFAEnrollResult]:
                input = m.UserMFAEnrollRequest(user_id=user_id, mfa_provider=mfa_provider, code=code)
                response = self.request.post("user/mfa/enroll", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserMFAEnrollResult(**response.raw_result)
                return response

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
                response = self.request.post("user/mfa/start", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserMFAStartResult(**response.raw_result)
                return response

            #   - path: authn::/v1/user/mfa/verify
            # https://dev.pangea.cloud/docs/api/authn#verify-an-mfa-code
            def verify(
                self, user_id: str, mfa_provider: m.MFAProvider, code: str
            ) -> PangeaResponse[m.UserMFAVerifyResult]:
                input = m.UserMFAverifyRequest(user_id=user_id, mfa_provider=mfa_provider, code=code)
                response = self.request.post("user/mfa/verify", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserMFAVerifyResult(**response.raw_result)
                return response

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
                response = self.request.post("user/profile/get", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserProfileGetResult(**response.raw_result)
                return response

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
                response = self.request.post("user/profile/update", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserProfileUpdateResult(**response.raw_result)
                return response

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
                response = self.request.post("user/invite/list", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserInviteListResult(**response.raw_result)
                return response

            #   - path: authn::/v1/user/invite/delete
            # https://dev.pangea.cloud/docs/api/authn#delete-an-invite
            def delete(self, id: str) -> PangeaResponse[m.UserInviteDeleteResult]:
                input = m.UserInviteDeleteRequest(id=id)
                response = self.request.post("user/invite/delete", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserInviteDeleteResult(**response.raw_result)
                return response

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
            response = self.request.post("flow/complete", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.FlowCompleteResult(**response.raw_result)
            return response

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
            response = self.request.post("flow/start", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.FlowStartResult(**response.raw_result)
            return response

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
                response = self.request.post("flow/reset/password", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.FlowResetPasswordResult(**response.raw_result)
                return response

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
                    response = self.request.post("flow/enroll/mfa/complete", data=input.dict(exclude_none=True))
                    if response.raw_result is not None:
                        response.result = m.FlowEnrollMFAcompleteResult(**response.raw_result)
                    return response

                #   - path: authn::/v1/flow/enroll/mfa/start
                # https://dev.pangea.cloud/docs/api/authn#start-the-process-of-enrolling-an-mfa
                def start(
                    self, flow_id: str, mfa_provider: m.MFAProvider, phone: Optional[str] = None
                ) -> PangeaResponse[m.FlowEnrollMFAStartResult]:
                    input = m.FlowEnrollMFAStartRequest(flow_id=flow_id, mfa_provider=mfa_provider, phone=phone)
                    response = self.request.post("flow/enroll/mfa/start", data=input.dict(exclude_none=True))
                    if response.raw_result is not None:
                        response.result = m.FlowEnrollMFAStartResult(**response.raw_result)
                    return response

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
                response = self.request.post("flow/signup/password", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.FlowSignupPasswordResult(**response.raw_result)
                return response

            #   - path: authn::/v1/flow/signup/social
            # https://dev.pangea.cloud/docs/api/authn#signup-a-new-account-using-a-social-provider
            def social(self, flow_id: str, cb_state: str, cb_code: str) -> PangeaResponse[m.FlowSignupSocialResult]:
                input = m.FlowSignupSocialRequest(flow_id=flow_id, cb_state=cb_state, cb_code=cb_code)
                response = self.request.post("flow/signup/social", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.FlowSignupSocialResult(**response.raw_result)
                return response

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
                response = self.request.post("flow/verify/captcha", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.FlowVerifyCaptchaResult(**response.raw_result)
                return response

            #   - path: authn::/v1/flow/verify/email
            # https://dev.pangea.cloud/docs/api/authn#verify-an-email-address-during-a-signup-or-signin-flow
            def email(
                self, flow_id: str, cb_state: Optional[str] = None, cb_code: Optional[str] = None
            ) -> PangeaResponse[m.FlowVerifyEmailResult]:
                input = m.FlowVerifyEmailRequest(flow_id=flow_id, cb_state=cb_state, cb_code=cb_code)
                response = self.request.post("flow/verify/email", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.FlowVerifyEmailResult(**response.raw_result)
                return response

            #   - path: authn::/v1/flow/verify/password
            # https://dev.pangea.cloud/docs/api/authn#sign-in-with-a-password
            def password(
                self, flow_id: str, password: Optional[str] = None, cancel: Optional[bool] = None
            ) -> PangeaResponse[m.FlowVerifyPasswordResult]:
                input = m.FlowVerifyPasswordRequest(flow_id=flow_id, password=password, cancel=cancel)
                response = self.request.post("flow/verify/password", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.FlowVerifyPasswordResult(**response.raw_result)
                return response

            #   - path: authn::/v1/flow/verify/social
            # https://dev.pangea.cloud/docs/api/authn#signin-with-a-social-provider
            def social(self, flow_id: str, cb_state: str, cb_code: str) -> PangeaResponse[m.FlowVerifySocialResult]:
                input = m.FlowVerifySocialRequest(flow_id=flow_id, cb_state=cb_state, cb_code=cb_code)
                response = self.request.post("flow/verify/social", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.FlowVerifySocialResult(**response.raw_result)
                return response

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
                    response = self.request.post("flow/verify/mfa/complete", data=input.dict(exclude_none=True))
                    if response.raw_result is not None:
                        response.result = m.FlowVerifyMFACompleteResult(**response.raw_result)
                    return response

                #   - path: authn::/v1/flow/verify/mfa/start
                # https://dev.pangea.cloud/docs/api/authn#start-the-process-of-mfa-verification
                def start(
                    self, flow_id: str, mfa_provider: m.MFAProvider
                ) -> PangeaResponse[m.FlowVerifyMFAStartResult]:
                    input = m.FlowVerifyMFAStartRequest(flow_id=flow_id, mfa_provider=mfa_provider)
                    response = self.request.post("flow/verify/mfa/start", data=input.dict(exclude_none=True))
                    if response.raw_result is not None:
                        response.result = m.FlowVerifyMFAStartResult(**response.raw_result)
                    return response

    # class Token(ServiceBase):
    #     service_name: str = SERVICE_NAME
    #     version: str = VERSION

    #     def __init__(
    #         self,
    #         token,
    #         config=None,
    #       logger_name="pangea",
    #     ):
    #         super().__init__(token, config, logger_name=logger_name)

    #     # https://dev.pangea.cloud/docs/api/authn?focus=authn#invalidate-a-session-by-session-id-using-a-client-token
    #     def list(self, ) -> PangeaResponse[m.ClientSessionInvalidateResult]:
    #         input = m.ClientSessionInvalidateRequest(token=token, session_id=session_id)
    #         response = self.request.post("client/session/invalidate", data=input.dict(exclude_none=True))
    #         if response.raw_result is not None:
    #             response.result = m.ClientSessionInvalidateResult(**response.raw_result)
    #         return response

# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from typing import List, Optional

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
    ):
        super().__init__(token, config)
        self.user = AuthN.User(token, config)
        self.password = AuthN.Password(token, config)

    # https://dev.pangea.cloud/docs/api/authn/#complete-a-login # FIXME: Update url once in prod
    def userinfo(self, code: str) -> PangeaResponse[m.UserinfoResult]:
        input = m.UserinfoRequest(code=code)

        response = self.request.post("userinfo", data=input.dict(exclude_none=True))
        if response.raw_result is not None:
            response.result = m.UserinfoResult(**response.raw_result)
        return response

    class Password(ServiceBase):
        service_name: str = SERVICE_NAME
        version: str = VERSION

        def __init__(
            self,
            token,
            config=None,
        ):
            super().__init__(token, config)

        #   - path: authn::/v1/password/update
        # https://dev.pangea.cloud/docs/api/authn#change-a-users-password   # FIXME: Update url once in prod
        def update(self, email: str, old_secret: str, new_secret: str) -> PangeaResponse[m.PasswordUpdateResult]:
            input = m.PasswordUpdateRequest(email=email, old_secret=old_secret, new_secret=new_secret)
            response = self.request.post("password/update", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.PasswordUpdateResult(**response.raw_result)
            return response

    class User(ServiceBase):
        service_name: str = SERVICE_NAME
        version: str = VERSION

        def __init__(
            self,
            token,
            config=None,
        ):
            super().__init__(token, config)
            self.profile = AuthN.User.Profile(token, config)
            self.invites = AuthN.User.Invites(token, config)

        #   - path: authn::/v1/user/create
        # https://dev.pangea.cloud/docs/api/authn#create-user   # FIXME: Update url once in prod
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
        # https://dev.pangea.cloud/docs/api/authn#delete-a-user # FIXME: Update url once in prod
        def delete(self, email: str) -> PangeaResponse[m.UserDeleteResult]:
            input = m.UserDeleteRequest(email=email)
            response = self.request.post("user/delete", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.UserDeleteResult(**response.raw_result)
            return response

        # https://dev.pangea.cloud/docs/api/authn/#administration-user-update # FIXME: Update url once in prod
        def update(
            self,
            identity: Optional[str] = None,
            email: Optional[str] = None,
            authenticator: Optional[str] = None,
            disabled: Optional[bool] = None,
            require_mfa: Optional[bool] = None,
        ) -> PangeaResponse[m.UserUpdateResult]:
            input = m.UserUpdateRequest(
                identity=identity,
                email=email,
                authenticator=authenticator,
                disabled=disabled,
                require_mfa=require_mfa,
            )

            response = self.request.post("user/update", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.UserUpdateResult(**response.raw_result)
            return response

        #   - path: authn::/v1/user/invite
        # https://dev.pangea.cloud/docs/api/authn#invite-a-user # FIXME: Update url once in prod
        def invite(
            self,
            inviter: str,
            email: str,
            callback: str,
            state: str,
            invite_org: Optional[str] = None,
            require_mfa: Optional[bool] = None,
        ) -> PangeaResponse[m.UserInviteResult]:
            input = m.UserInviteRequest(
                inviter=inviter,
                email=email,
                callback=callback,
                state=state,
                invite_org=invite_org,
                require_mfa=require_mfa,
            )
            response = self.request.post("user/invite", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.UserInviteResult(**response.raw_result)
            return response

        #   - path: authn::/v1/user/list
        # https://dev.pangea.cloud/docs/api/authn#list-users # FIXME: Update url once in prod
        def list(self, scopes: m.Scopes, glob_scopes: m.Scopes) -> PangeaResponse[m.UserListResult]:
            input = m.UserListRequest(scopes=scopes, glob_scopes=glob_scopes)
            response = self.request.post("user/list", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.UserListResult(**response.raw_result)
            return response

        #   - path: authn::/v1/user/login
        # https://dev.pangea.cloud/docs/api/authn#user-login # FIXME: Update url once in prod
        def login(
            self, email: str, secret: str, scopes: Optional[m.Scopes] = None
        ) -> PangeaResponse[m.UserLoginResult]:
            input = m.UserLoginRequest(email=email, secret=secret, scopes=scopes)
            response = self.request.post("user/login", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.UserLoginResult(**response.raw_result)
            return response

        #   - path: authn::/v1/user/verify
        # https://dev.pangea.cloud/docs/api/authn#verify-a-user
        def verify(
            self, id_provider: m.IDProvider, email: str, authenticator: str
        ) -> PangeaResponse[m.UserVerifyResult]:
            input = m.UserVerifyRequest(id_provider=id_provider, email=email, authenticator=authenticator)
            response = self.request.post("user/login", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.UserVerifyResult(**response.raw_result)
            return response

        class MFA(ServiceBase):
            service_name: str = SERVICE_NAME
            version: str = VERSION

            def __init__(
                self,
                token,
                config=None,
            ):
                super().__init__(token, config)

            #   - path: authn::/v1/user/mfa/delete
            # https://dev.pangea.cloud/docs/api/authn#delete-mfa-enrollment-for-a-user
            def delete(self, user_id: str, mfa_provider: m.MFAProvider) -> PangeaResponse[m.UserMFAdeleteResult]:
                input = m.UserMFAdeleteRequest(user_id=user_id, mfa_provider=mfa_provider)
                response = self.request.post("user/mfa/delete", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserMFAdeleteResult(**response.raw_result)
                return response

            #   - path: authn::/v1/user/mfa/enroll
            # https://dev.pangea.cloud/docs/api/authn#enroll-mfa-for-a-user
            def enroll(
                self, user_id: str, mfa_provider: m.MFAProvider, code: str
            ) -> PangeaResponse[m.UserMFAenrollResult]:
                input = m.UserMFAenrollRequest(user_id=user_id, mfa_provider=mfa_provider, code=code)
                response = self.request.post("user/mfa/enroll", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserMFAenrollResult(**response.raw_result)
                return response

            #   - path: authn::/v1/user/mfa/start
            # https://dev.pangea.cloud/docs/api/authn#start-mfa-verification-for-a-user
            def start(
                self, user_id: str, mfa_provider: m.MFAProvider, enroll: Optional[bool] = None
            ) -> PangeaResponse[m.UserMFAstartResult]:
                input = m.UserMFAstartRequest(user_id=user_id, mfa_provider=mfa_provider, enroll=enroll)
                response = self.request.post("user/mfa/start", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserMFAenrollResult(**response.raw_result)
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
            ):
                super().__init__(token, config)

            #   - path: authn::/v1/user/profile/get
            # https://dev.pangea.cloud/docs/api/authn#get-user # FIXME: Update url once in prod
            def get(
                self, identity: Optional[str] = None, email: Optional[str] = None
            ) -> PangeaResponse[m.UserProfileGetResult]:
                input = m.UserProfileGetRequest(identity=identity, email=email)
                response = self.request.post("user/profile/get", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserProfileGetResult(**response.raw_result)
                return response

            #   - path: authn::/v1/user/profile/update
            # https://dev.pangea.cloud/docs/api/authn#update-user # FIXME: Update url once in prod
            def update(
                self,
                profile: m.Profile,
                identity: Optional[str] = None,
                email: Optional[str] = None,
                require_mfa: Optional[bool] = None,
                mfa_value: Optional[str] = None,
                mfa_provider: Optional[str] = None,
            ) -> PangeaResponse[m.UserProfileUpdateResult]:
                input = m.UserProfileUpdateRequest(
                    identity=identity,
                    email=email,
                    profile=profile,
                    require_mfa=require_mfa,
                    mfa_value=mfa_value,
                    mfa_provider=mfa_provider,
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
            ):
                super().__init__(token, config)

            #   - path: authn::/v1/user/invite/list
            # https://dev.pangea.cloud/docs/api/authn#list-invites # FIXME: Update url once in prod
            def list(self) -> PangeaResponse[m.UserInviteListResult]:
                response = self.request.post("user/invite/list", data={})
                if response.raw_result is not None:
                    response.result = m.UserInviteListResult(**response.raw_result)
                return response

            #   - path: authn::/v1/user/invite/delete
            # https://dev.pangea.cloud/docs/api/authn#delete-an-invite # FIXME: Update url once in prod
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
        ):
            super().__init__(token, config)

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
            self, cb_uri: str, email: Optional[str] = None, flow_types: Optional[List[str]] = None
        ) -> PangeaResponse[m.FlowStartResult]:
            input = m.FlowStartRequest(cb_uri=cb_uri, email=email, flow_types=flow_types)
            response = self.request.post("flow/start", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.FlowStartResult(**response.raw_result)
            return response

        class Enroll(ServiceBase):
            service_name: str = SERVICE_NAME
            version: str = VERSION

            def __init__(
                self,
                token,
                config=None,
            ):
                super().__init__(token, config)

            class MFA(ServiceBase):
                service_name: str = SERVICE_NAME
                version: str = VERSION

                def __init__(
                    self,
                    token,
                    config=None,
                ):
                    super().__init__(token, config)

                #   - path: authn::/v1/flow/enroll/mfa/complete
                # https://dev.pangea.cloud/docs/api/authn#complete-mfa-enrollment-by-verifying-a-trial-mfa-code
                def complete(
                    self, flow_id: str, code: str, cancel: Optional[bool] = None
                ) -> PangeaResponse[m.FlowEnrollMFAcompleteResult]:
                    input = m.FlowEnrollMFACompleteRequest()
                    response = self.request.post("flow/enroll/mfa/comple", data=input.dict(exclude_none=True))
                    if response.raw_result is not None:
                        response.result = m.FlowEnrollMFAcompleteResult(**response.raw_result)
                    return response

                #   - path: authn::/v1/flow/enroll/mfa/start
                # https://dev.pangea.cloud/docs/api/authn#start-the-process-of-enrolling-an-mfa
                def start(
                    self, flow_id: str, mfa_provider: m.MFAProvider
                ) -> PangeaResponse[m.FlowEnrollMFAstartResult]:
                    input = m.FlowEnrollMFAstartRequest(flow_id=flow_id, mfa_provider=mfa_provider)
                    response = self.request.post("flow/enroll/mfa/start", data=input.dict(exclude_none=True))
                    if response.raw_result is not None:
                        response.result = m.FlowEnrollMFAstartResult(**response.raw_result)
                    return response

        class Signup(ServiceBase):
            service_name: str = SERVICE_NAME
            version: str = VERSION

            def __init__(
                self,
                token,
                config=None,
            ):
                super().__init__(token, config)

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
            ):
                super().__init__(token, config)

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
            def email(self, flow_id: str, cb_state: str, cb_code: str) -> PangeaResponse[m.FlowVerifyEmailResult]:
                input = m.FlowVerifyEmailRequest(flow_id=flow_id, cb_state=cb_state, cb_code=cb_code)
                response = self.request.post("flow/verify/email", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.FlowVerifyEmailResult(**response.raw_result)
                return response

            #   - path: authn::/v1/flow/verify/password
            # https://dev.pangea.cloud/docs/api/authn#sign-in-with-a-password
            def password(self, flow_id: str, password: str) -> PangeaResponse[m.FlowVerifyPasswordResult]:
                input = m.FlowVerifyPasswordRequest(flow_id=flow_id, password=password)
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
                ):
                    super().__init__(token, config)

                #   - path: authn::/v1/flow/verify/mfa/complete
                # https://dev.pangea.cloud/docs/api/authn#complete-mfa-verification
                def complete(self, flow_id: str, code: str) -> PangeaResponse[m.FlowVerifyMFAcompleteResult]:
                    input = m.FlowVerifyMFAcompleteRequest()
                    response = self.request.post("flow/verify/mfa/complete", data=input.dict(exclude_none=True))
                    if response.raw_result is not None:
                        response.result = m.FlowVerifyMFAcompleteResult(**response.raw_result)
                    return response

                #   - path: authn::/v1/flow/verify/mfa/start
                # https://dev.pangea.cloud/docs/api/authn#start-the-process-of-mfa-verification
                def start(
                    self, flow_id: str, mfa_provider: m.MFAProvider
                ) -> PangeaResponse[m.FlowVerifyMFAstartResult]:
                    input = m.FlowVerifyMFAstartRequest(flow_id=flow_id, mfa_provider=mfa_provider)
                    response = self.request.post("flow/verify/mfa/start", data=input.dict(exclude_none=True))
                    if response.raw_result is not None:
                        response.result = m.FlowVerifyMFAstartResult(**response.raw_result)
                    return response

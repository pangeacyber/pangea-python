# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from typing import Dict, List, Optional

import pangea.services.authn.models as m
from pangea.response import PangeaResponse
from pangea.services.base import ServiceBase

SERVICE_NAME = "authn"
SUPPORT_MULTI_CONFIG = True


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

    service_name = SERVICE_NAME
    _support_multi_config = SUPPORT_MULTI_CONFIG

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
        service_name = SERVICE_NAME
        _support_multi_config = SUPPORT_MULTI_CONFIG

        def __init__(
            self,
            token,
            config=None,
            logger_name="pangea",
        ):
            super().__init__(token, config, logger_name=logger_name)

        # https://pangea.cloud/docs/api/authn#invalidate-session
        # - path: authn::/v1/session/invalidate
        def invalidate(self, session_id: str) -> PangeaResponse[m.SessionInvalidateResult]:
            """
            Invalidate Session

            Invalidate a session by session ID.

            OperationId: authn_post_v1_session_invalidate

            Args:
                session_id (str): An ID for a token

            Returns:
                A PangeaResponse with an empty object in the response.result field.

            Examples:
                authn.session.invalidate(
                    session_id="pmt_zppkzrjguxyblaia6itbiesejn7jejnr",
                )
            """
            input = m.SessionInvalidateRequest(session_id=session_id)
            response = self.request.post("v1/session/invalidate", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.SessionInvalidateResult(**response.raw_result)
            return response

        # https://pangea.cloud/docs/api/authn#list-session-service-token
        # - path: authn::/v1/session/list
        def list(
            self,
            filter: Optional[Dict] = None,
            last: Optional[str] = None,
            order: Optional[m.ItemOrder] = None,
            order_by: Optional[m.SessionListOrderBy] = None,
            size: Optional[int] = None,
        ) -> PangeaResponse[m.SessionListResults]:
            """
            List session (service token)

            List sessions.

            OperationId: authn_post_v1_session_list

            Args:
                filter (dict, optional):
                last (str, optional): Reflected value from a previous response to obtain the next page of results.
                order (m.ItemOrder, optional): Order results asc(ending) or desc(ending).
                order_by (m.SessionListOrderBy, optional): Which field to order results by.
                size (int, optional): Maximum results to include in the response. Minimum: 1.

            Returns:
                A PangeaResponse with a list of sessions in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn#list-session-service-token).

            Examples:
                response = authn.session.list()
            """
            input = m.SessionListRequest(filter=filter, last=last, order=order, order_by=order_by, size=size)
            response = self.request.post("v1/session/list", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.SessionListResults(**response.raw_result)
            return response

        # https://pangea.cloud/docs/api/authn#log-out-service-token
        # - path: authn::/v1/session/logout
        def logout(self, user_id: str) -> PangeaResponse[m.SessionLogoutResult]:
            """
            Log out (service token)

            Invalidate all sessions belonging to a user.

            OperationId: authn_post_v1_session_logout

            Args:
                user_id (str): The identity of a user or a service.

            Returns:
                A PangeaResponse with an empty object in the response.result field.

            Examples:
                authn.session.logout(
                    user_id="pui_xpkhwpnz2cmegsws737xbsqnmnuwtvm5",
                )
            """
            input = m.SessionLogoutRequest(user_id=user_id)
            response = self.request.post("v1/session/logout", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.SessionLogoutResult(**response.raw_result)
            return response

    class Client(ServiceBase):
        service_name = SERVICE_NAME
        _support_multi_config = SUPPORT_MULTI_CONFIG

        def __init__(
            self,
            token,
            config=None,
            logger_name="pangea",
        ):
            super().__init__(token, config, logger_name=logger_name)
            self.session = AuthN.Client.Session(token, config, logger_name=logger_name)
            self.password = AuthN.Client.Password(token, config, logger_name=logger_name)
            self.token_enpoints = AuthN.Client.Token(token, config, logger_name=logger_name)

        # https://pangea.cloud/docs/api/authn#get-user-client-token
        # - path: authn::/v1/client/userinfo
        def userinfo(self, code: str) -> PangeaResponse[m.ClientUserinfoResult]:
            """
            Get User (client token)

            Retrieve the logged in user's token and information.

            OperationId: authn_post_v1_client_userinfo

            Args:
                code (str): A one-time ticket

            Returns:
                A PangeaResponse with credentials for a login session in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn#get-user-client-token).

            Examples:
                response = authn.client.userinfo(
                    code="pmc_d6chl6qulpn3it34oerwm3cqwsjd6dxw",
                )
            """
            input = m.ClientUserinfoRequest(code=code)
            response = self.request.post("v1/client/userinfo", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.ClientUserinfoResult(**response.raw_result)
            return response

        # https://pangea.cloud/docs/api/authn#get-jwt-verification-keys
        # - path: authn::/v1/client/jwks
        def jwks(
            self,
        ) -> PangeaResponse[m.ClientJWKSResult]:
            """
            Get JWT verification keys

            Get JWT verification keys.

            OperationId: authn_post_v1_client_jwks

            Returns:
                A PangeaResponse with jwt verification keys in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn#get-jwt-verification-keys).

            Examples:
                response = authn.client.jwks()
            """
            response = self.request.post("v1/client/jwks", {})
            if response.raw_result is not None:
                response.result = m.ClientJWKSResult(**response.raw_result)
            return response

        class Session(ServiceBase):
            service_name = SERVICE_NAME
            _support_multi_config = SUPPORT_MULTI_CONFIG

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            # https://pangea.cloud/docs/api/authn#invalidate-session-client
            # - path: authn::/v1/client/session/invalidate
            def invalidate(self, token: str, session_id: str) -> PangeaResponse[m.ClientSessionInvalidateResult]:
                """
                Invalidate Session | Client

                Invalidate a session by session ID using a client token.

                OperationId: authn_post_v1_client_session_invalidate

                Args:
                    token (str): A user token value
                    session_id (str): An ID for a token

                Returns:
                    A PangeaResponse with an empty object in the response.result field.

                Examples:
                    authn.client.session.invalidate(
                        token="ptu_wuk7tvtpswyjtlsx52b7yyi2l7zotv4a",
                        session_id="pmt_zppkzrjguxyblaia6itbiesejn7jejnr",
                    )
                """
                input = m.ClientSessionInvalidateRequest(token=token, session_id=session_id)
                response = self.request.post("v1/client/session/invalidate", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.ClientSessionInvalidateResult(**response.raw_result)
                return response

            # https://pangea.cloud/docs/api/authn#list-sessions-client-token
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
                """
                List sessions (client token)

                List sessions using a client token.

                OperationId: authn_post_v1_client_session_list

                Args:
                    token (str): A user token value
                    filter (dict, optional):
                    last (str, optional): Reflected value from a previous response to obtain the next page of results.
                    order (m.ItemOrder, optional): Order results asc(ending) or desc(ending).
                    order_by (m.SessionListOrderBy, optional): Which field to order results by.
                    size (int, optional): Maximum results to include in the response. Minimum: 1.

                Returns:
                    A PangeaResponse with a list of sessions in the response.result field.
                        Available response fields can be found in our
                        [API Documentation](https://pangea.cloud/docs/api/authn#list-sessions-client-token).

                Examples:
                    response = authn.client.session.list(
                        token="ptu_wuk7tvtpswyjtlsx52b7yyi2l7zotv4a",
                    )
                """
                input = m.ClientSessionListRequest(
                    token=token, filter=filter, last=last, order=order, order_by=order_by, size=size
                )
                response = self.request.post("v1/client/session/list", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.ClientSessionListResults(**response.raw_result)
                return response

            # https://pangea.cloud/docs/api/authn#log-out-client-token
            # - path: authn::/v1/client/session/logout
            def logout(self, token: str) -> PangeaResponse[m.ClientSessionLogoutResult]:
                """
                Log out (client token)

                Log out the current user's session.

                OperationId: authn_post_v1_client_session_logout

                Args:
                    token (str): A user token value

                Returns:
                    A PangeaResponse with an empty object in the response.result field.

                Examples:
                    authn.client.session.logout(
                        token="ptu_wuk7tvtpswyjtlsx52b7yyi2l7zotv4a",
                    )
                """
                input = m.ClientSessionLogoutRequest(token=token)
                response = self.request.post("v1/client/session/logout", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.ClientSessionLogoutResult(**response.raw_result)
                return response

            # https://pangea.cloud/docs/api/authn#refresh-a-session
            # - path: authn::/v1/client/session/refresh
            def refresh(
                self, refresh_token: str, user_token: Optional[str] = None
            ) -> PangeaResponse[m.ClientSessionRefreshResult]:
                """
                Refresh a Session

                Refresh a session token.

                OperationId: authn_post_v1_client_session_refresh

                Args:
                    refresh_token (str): A refresh token value
                    user_token (str, optional): A user token value

                Returns:
                    A PangeaResponse with credentials for a login session in the response.result field.
                        Available response fields can be found in our
                        [API Documentation](https://pangea.cloud/docs/api/authn#refresh-a-session).

                Examples:
                    response = authn.client.session.refresh(
                        refresh_token="ptr_xpkhwpnz2cmegsws737xbsqnmnuwtbm5",
                        user_token="ptu_wuk7tvtpswyjtlsx52b7yyi2l7zotv4a",
                    )
                """
                input = m.ClientSessionRefreshRequest(refresh_token=refresh_token, user_token=user_token)
                response = self.request.post("v1/client/session/refresh", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.ClientSessionRefreshResult(**response.raw_result)
                return response

        class Password(ServiceBase):
            service_name = SERVICE_NAME
            _support_multi_config = SUPPORT_MULTI_CONFIG

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            # https://pangea.cloud/docs/api/authn#change-a-users-password
            # - path: authn::/v1/client/password/change
            def change(
                self, token: str, old_password: str, new_password: str
            ) -> PangeaResponse[m.ClientPasswordChangeResult]:
                """
                Change a user's password

                Change a user's password given the current password.

                OperationId: authn_post_v1_client_password_change

                Args:
                    token (str): A user token value
                    old_password (str):
                    new_password (str):

                Returns:
                    A PangeaResponse with an empty object in the response.result field.

                Examples:
                    authn.client.password.change(
                        token="ptu_wuk7tvtpswyjtlsx52b7yyi2l7zotv4a",
                        old_password="hunter2",
                        new_password="My2n+Password",
                    )
                """
                input = m.ClientPasswordChangeRequest(token=token, old_password=old_password, new_password=new_password)
                response = self.request.post("v1/client/password/change", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.ClientPasswordChangeResult(**response.raw_result)
                return response

        class Token(ServiceBase):
            service_name = SERVICE_NAME
            _support_multi_config = SUPPORT_MULTI_CONFIG

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            def check(self, token: str) -> PangeaResponse[m.ClientTokenCheckResult]:
                """
                Check a token

                Look up a token and return its contents.

                OperationId: authn_post_v1_client_token_check

                Args:
                    token (str): A token value

                Returns:
                    A PangeaResponse with a token and its information in the response.result field.
                        Available response fields can be found in our
                        [API Documentation](https://pangea.cloud/docs/api/authn#check-a-token).

                Examples:
                    response = authn.client.token.check(
                        token="ptu_wuk7tvtpswyjtlsx52b7yyi2l7zotv4a",
                    )
                """
                input = m.ClientTokenCheckRequest(token=token)
                response = self.request.post("v1/client/token/check", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.ClientTokenCheckResult(**response.raw_result)
                return response

    class User(ServiceBase):
        service_name = SERVICE_NAME
        _support_multi_config = SUPPORT_MULTI_CONFIG

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
            self.password = AuthN.User.Password(token, config, logger_name=logger_name)

        # https://pangea.cloud/docs/api/authn#create-user
        # - path: authn::/v1/user/create
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
            """
            Create User

            Create a user.

            OperationId: authn_post_v1_user_create

            Args:
                email (str): An email address
                authenticator (str): A provider-specific authenticator, such as a password or a social identity.
                id_provider (m.IDProvider, optional): Mechanism for authenticating a user's identity
                verified (bool, optional): True if the user's email has been verified
                require_mfa (bool, optional): True if the user must use MFA during authentication
                profile (m.Profile, optional): A user profile as a collection of string properties
                scopes (m.Scopes, optional): A list of scopes

            Returns:
                A PangeaResponse with a user and its information in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn#create-user).

            Examples:
                response = authn.user.create(
                    email="joe.user@email.com",
                    password="My1s+Password",
                    id_provider=IDProvider.PASSWORD
                )
            """
            input = m.UserCreateRequest(
                email=email,
                authenticator=authenticator,
                id_provider=id_provider,
                verified=verified,
                require_mfa=require_mfa,
                profile=profile,
                scopes=scopes,
            )
            response = self.request.post("v1/user/create", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.UserCreateResult(**response.raw_result)
            return response

        # https://pangea.cloud/docs/api/authn#delete-user
        # - path: authn::/v1/user/delete
        def delete(self, email: Optional[str] = None, id: Optional[str] = None) -> PangeaResponse[m.UserDeleteResult]:
            """
            Delete User

            Delete a user.

            OperationId: authn_post_v1_user_delete

            Args:
                email (str, optional): An email address
                id (str, optional): The identity of a user or a service

            Returns:
                A PangeaResponse with an empty object in the response.result field.

            Examples:
                authn.user.delete(email="example@example.com")
            """
            input = m.UserDeleteRequest(email=email, id=id)
            response = self.request.post("v1/user/delete", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.UserDeleteResult(**response.raw_result)
            return response

        # https://pangea.cloud/docs/api/authn#update-users-settings
        # - path: authn::/v1/user/update
        def update(
            self,
            id: Optional[str] = None,
            email: Optional[str] = None,
            authenticator: Optional[str] = None,
            disabled: Optional[bool] = None,
            require_mfa: Optional[bool] = None,
            verified: Optional[bool] = None,
        ) -> PangeaResponse[m.UserUpdateResult]:
            """
            Update user's settings

            Update user's settings.

            OperationId: authn_post_v1_user_update

            Args:
                id (str, optional): The identity of a user or a service
                email (str, optional): An email address
                authenticator (str, optional): A provider-specific authenticator, 
                    such as a password or a social identity.
                disabled (bool, optional): New disabled value. 
                    Disabling a user account will prevent them from logging in.
                require_mfa (bool, optional): True if the user must use MFA during authentication
                verified (bool, optional): True if the user's email has been verified

            Returns:
                A PangeaResponse with a user and its information in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn#update-users-settings).

            Examples:
                response = authn.user.update(
                    email="joe.user@email.com",
                    require_mfa=True,
                )
            """
            input = m.UserUpdateRequest(
                id=id,
                email=email,
                authenticator=authenticator,
                disabled=disabled,
                require_mfa=require_mfa,
                verified=verified,
            )

            response = self.request.post("v1/user/update", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.UserUpdateResult(**response.raw_result)
            return response

        # https://pangea.cloud/docs/api/authn#invite-user
        # - path: authn::/v1/user/invite
        def invite(
            self,
            inviter: str,
            email: str,
            callback: str,
            state: str,
            require_mfa: Optional[bool] = None,
        ) -> PangeaResponse[m.UserInviteResult]:
            """
            Invite User

            Send an invitation to a user.

            OperationId: authn_post_v1_user_invite

            Args:
                inviter (str): An email address
                email (str): An email address
                callback (str): A login callback URI
                state (str): State tracking string for login callbacks
                require_mfa (bool, optional): Require the user to authenticate with MFA
            
            Returns:
                A PangeaResponse with a pending user invitation in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn#invite-user).

            Examples:
                response = authn.user.invite(
                    inviter="admin@email.com",
                    email="joe.user@email.com",
                    callback="/callback",
                    state="pcb_zurr3lkcwdp5keq73htsfpcii5k4zgm7"
                    require_mfa=True,
                )
            """
            input = m.UserInviteRequest(
                inviter=inviter,
                email=email,
                callback=callback,
                state=state,
                require_mfa=require_mfa,
            )
            response = self.request.post("v1/user/invite", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.UserInviteResult(**response.raw_result)
            return response

        # https://pangea.cloud/docs/api/authn#list-users
        # - path: authn::/v1/user/list
        def list(
            self,
            filter: Optional[Dict] = None,
            last: Optional[str] = None,
            order: Optional[m.ItemOrder] = None,
            order_by: Optional[m.UserListOrderBy] = None,
            size: Optional[int] = None,
        ) -> PangeaResponse[m.UserListResult]:
            """
            List Users

            Look up users by scopes.

            OperationId: authn_post_v1_user_list

            Args:
                filter (dict, optional):
                last (str, optional): Reflected value from a previous response to obtain the next page of results.
                order (m.ItemOrder, optional): Order results asc(ending) or desc(ending).
                order_by (m.UserListOrderBy, optional): Which field to order results by.
                size (int, optional): Maximum results to include in the response. Minimum: 1.

            Returns:
                A PangeaResponse with a list of users in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn#list-users).

            Examples:
                response = authn.user.list()
            """
            input = m.UserListRequest(
                filter=filter,
                last=last,
                order=order,
                order_by=order_by,
                size=size,
            )
            response = self.request.post("v1/user/list", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.UserListResult(**response.raw_result)
            return response

        # https://pangea.cloud/docs/api/authn#verify-user
        # - path: authn::/v1/user/verify
        def verify(
            self, id_provider: m.IDProvider, email: str, authenticator: str
        ) -> PangeaResponse[m.UserVerifyResult]:
            """
            Verify User

            Verify a user's primary authentication.

            OperationId: authn_post_v1_user_verify

            Args:
                id_provider (m.IDProvider): Mechanism for authenticating a user's identity
                email (str): An email address
                authenticator (str): A provider-specific authenticator, such as a password or a social identity.

            Returns:
                A PangeaResponse with a user and its information in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn#verify-user).

            Examples:
                response = authn.user.verify(
                    id_provider=IDProvider.PASSWORD,
                    email="joe.user@email.com",
                    authenticator="My1s+Password",
                )
            """
            input = m.UserVerifyRequest(id_provider=id_provider, email=email, authenticator=authenticator)
            response = self.request.post("v1/user/verify", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.UserVerifyResult(**response.raw_result)
            return response

        class Password(ServiceBase):
            service_name = SERVICE_NAME
            _support_multi_config = SUPPORT_MULTI_CONFIG

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            # https://pangea.cloud/docs/api/authn#user-password-reset
            # - path: authn::/v1/user/password/reset
            def reset(self, user_id: str, new_password: str) -> PangeaResponse[m.UserPasswordResetResult]:
                """
                User Password Reset

                Manually reset a user's password.

                OperationId: authn_post_v1_user_password_reset

                Args:
                    user_id (str): The identity of a user or a service
                    new_password (str): A new password

                Returns:
                    A PangeaResponse with an empty object in the response.result field.

                Examples:
                    response = authn.user.password.reset(
                      user_id="pui_xpkhwpnz2cmegsws737xbsqnmnuwtvm5",
                    )
                """
                input = m.UserPasswordResetRequest(user_id=user_id, new_password=new_password)
                response = self.request.post("v1/user/password/reset", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserPasswordResetResult(**response.raw_result)
                return response

        class Login(ServiceBase):
            service_name = SERVICE_NAME
            _support_multi_config = SUPPORT_MULTI_CONFIG

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            # https://pangea.cloud/docs/api/authn#login-with-a-password
            # - path: authn::/v1/user/login/password
            def password(
                self, email: str, password: str, extra_profile: Optional[m.Profile] = None
            ) -> PangeaResponse[m.UserLoginResult]:
                """
                Login with a password

                Login a user with a password and return the user's token and information.

                OperationId: authn_post_v1_user_login_password

                Args:
                    email (str): An email address
                    password (str): The user's password
                    extra_profile (m.Profile, optional): A user profile as a collection of string properties

                Returns:
                    A PangeaResponse with credentials for a login session in the response.result field.
                        Available response fields can be found in our
                        [API Documentation](https://pangea.cloud/docs/api/authn#login-with-a-password).

                Examples:
                    response = authn.user.login.password(
                        email="joe.user@email.com",
                        password="My1s+Password",
                        extra_profile={
                            "first_name": "Joe",
                            "last_name": "User",
                        },
                    )
                """
                input = m.UserLoginPasswordRequest(email=email, password=password, extra_profile=extra_profile)
                response = self.request.post("v1/user/login/password", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserLoginResult(**response.raw_result)
                return response

            # https://pangea.cloud/docs/api/authn#login-with-a-social-provider
            # - path: authn::/v1/user/login/social
            def social(
                self, provider: m.IDProvider, email: str, social_id: str, extra_profile: Optional[m.Profile] = None
            ) -> PangeaResponse[m.UserLoginResult]:
                """
                Login with a social provider

                Login a user by their social ID and return the user's token and information.

                OperationId: authn_post_v1_user_login_social

                Args:
                    provider (m.IDProvider): Social identity provider for authenticating a user's identity
                    email (str): An email address
                    social_id (str): User's social ID with the provider
                    extra_profile (m.Profile, optional): A user profile as a collection of string properties

                Returns:
                    A PangeaResponse with credentials for a login session in the response.result field.
                        Available response fields can be found in our
                        [API Documentation](https://pangea.cloud/docs/api/authn#login-with-a-social-provider).

                Examples:
                    response = authn.user.login.social(
                        provider=IDProvider.GOOGLE,
                        email="joe.user@email.com",
                        social_id="My1s+Password",
                        extra_profile={
                            "first_name": "Joe",
                            "last_name": "User",
                        },
                    )
                """
                input = m.UserLoginSocialRequest(
                    provider=provider, email=email, social_id=social_id, extra_profile=extra_profile
                )
                response = self.request.post("v1/user/login/social", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserLoginResult(**response.raw_result)
                return response

        class MFA(ServiceBase):
            service_name = SERVICE_NAME
            _support_multi_config = SUPPORT_MULTI_CONFIG

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            # https://pangea.cloud/docs/api/authn#delete-mfa-enrollment
            # - path: authn::/v1/user/mfa/delete
            def delete(self, user_id: str, mfa_provider: m.MFAProvider) -> PangeaResponse[m.UserMFADeleteResult]:
                """
                Delete MFA Enrollment

                Delete MFA enrollment for a user.

                OperationId: authn_post_v1_user_mfa_delete

                Args:
                    user_id (str): The identity of a user or a service
                    mfa_provider (m.MFAProvider): Additional mechanism for authenticating a user's identity

                Returns:
                    A PangeaResponse with an empty object in the response.result field.

                Examples:
                    authn.user.mfa.delete(
                        user_id="pui_zgp532cx6opljeavvllmbi3iwmq72f7f",
                        MFAProvider.TOTP,
                    )
                """
                input = m.UserMFADeleteRequest(user_id=user_id, mfa_provider=mfa_provider)
                response = self.request.post("v1/user/mfa/delete", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserMFADeleteResult(**response.raw_result)
                return response

            # https://pangea.cloud/docs/api/authn#enroll-in-mfa
            # - path: authn::/v1/user/mfa/enroll
            def enroll(
                self, user_id: str, mfa_provider: m.MFAProvider, code: str
            ) -> PangeaResponse[m.UserMFAEnrollResult]:
                """
                Enroll In MFA

                Enroll in MFA for a user by proving the user has access to an MFA verification code.

                OperationId: authn_post_v1_user_mfa_enroll

                Args:
                    user_id (str): The identity of a user or a service
                    mfa_provider (m.MFAProvider): Additional mechanism for authenticating a user's identity
                    code (str): A six digit MFA code

                Returns:
                    A PangeaResponse with an empty object in the response.result field.

                Examples:
                    authn.user.mfa.enroll(
                        user_id="pui_zgp532cx6opljeavvllmbi3iwmq72f7f",
                        mfa_provider=MFAProvider.TOTP,
                        code="999999",
                    )
                """
                input = m.UserMFAEnrollRequest(user_id=user_id, mfa_provider=mfa_provider, code=code)
                response = self.request.post("v1/user/mfa/enroll", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserMFAEnrollResult(**response.raw_result)
                return response

            # https://pangea.cloud/docs/api/authn#user-start-mfa-verification
            # - path: authn::/v1/user/mfa/start
            def start(
                self,
                user_id: str,
                mfa_provider: m.MFAProvider,
                enroll: Optional[bool] = None,
                phone: Optional[str] = None,
            ) -> PangeaResponse[m.UserMFAStartResult]:
                """
                Start MFA Verification

                Start MFA verification for a user, generating a new one-time code, and 
                    sending it if necessary. When enrolling TOTP, this returns the TOTP secret.

                OperationId: authn_post_v1_user_mfa_start

                Args:
                    user_id (str): The identity of a user or a service
                    mfa_provider (m.MFAProvider): Additional mechanism for authenticating a user's identity
                    enroll (bool, optional):
                    phone (str, optional): A phone number

                Returns:
                    A PangeaResponse with a totp secret in the response.result field.
                        Available response fields can be found in our
                        [API Documentation](https://pangea.cloud/docs/api/authn#user-start-mfa-verification).

                Examples:
                    response = authn.user.mfa.start(
                        user_id="pui_zgp532cx6opljeavvllmbi3iwmq72f7f",
                        mfa_provider=MFAProvider.SMS_OTP,
                        phone="1-808-555-0173",
                    )
                """
                input = m.UserMFAStartRequest(user_id=user_id, mfa_provider=mfa_provider, enroll=enroll, phone=phone)
                response = self.request.post("v1/user/mfa/start", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserMFAStartResult(**response.raw_result)
                return response

            # https://pangea.cloud/docs/api/authn#verify-an-mfa-code
            # - path: authn::/v1/user/mfa/verify
            def verify(
                self, user_id: str, mfa_provider: m.MFAProvider, code: str
            ) -> PangeaResponse[m.UserMFAVerifyResult]:
                """
                Verify An MFA Code

                Verify that the user has access to an MFA verification code.

                OperationId: authn_post_v1_user_mfa_verify

                Args:
                    user_id (str): The identity of a user or a service
                    mfa_provider (m.MFAProvider): Additional mechanism for authenticating a user's identity
                    code (str): A six digit MFA code

                Returns:
                    A PangeaResponse with an empty object in the response.result field.

                Examples:
                    authn.user.mfa.verify(
                        user_id="pui_zgp532cx6opljeavvllmbi3iwmq72f7f",
                        mfa_provider=MFAProvider.TOTP,
                        code="999999",
                    )
                """
                input = m.UserMFAverifyRequest(user_id=user_id, mfa_provider=mfa_provider, code=code)
                response = self.request.post("v1/user/mfa/verify", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserMFAVerifyResult(**response.raw_result)
                return response

        class Profile(ServiceBase):
            service_name = SERVICE_NAME
            _support_multi_config = SUPPORT_MULTI_CONFIG

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            # https://pangea.cloud/docs/api/authn#get-user
            # - path: authn::/v1/user/profile/get
            def get(
                self, id: Optional[str] = None, email: Optional[str] = None
            ) -> PangeaResponse[m.UserProfileGetResult]:
                """
                Get user

                Get user's information by identity or email.

                OperationId: authn_post_v1_user_profile_get

                Args:
                    id (str, optional): The identity of a user or a service
                    email (str, optional): An email address

                Returns:
                    A PangeaResponse with a user and its information in the response.result field.
                        Available response fields can be found in our
                        [API Documentation](https://pangea.cloud/docs/api/authn#get-user).

                Examples:
                    response = authn.user.profile.get(
                        email="joe.user@email.com",
                    )
                """
                input = m.UserProfileGetRequest(id=id, email=email)
                response = self.request.post("v1/user/profile/get", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserProfileGetResult(**response.raw_result)
                return response

            # https://pangea.cloud/docs/api/authn#update-user
            # - path: authn::/v1/user/profile/update
            def update(
                self,
                profile: m.Profile,
                id: Optional[str] = None,
                email: Optional[str] = None,
            ) -> PangeaResponse[m.UserProfileUpdateResult]:
                """
                Update user

                Update user's information by identity or email.

                OperationId: authn_post_v1_user_profile_update

                Args:
                    profile (m.Profile): Updates to a user profile
                    id (str, optional): The identity of a user or a service
                    email (str, optional): An email address

                Returns:
                    A PangeaResponse with a user and its information in the response.result field.
                        Available response fields can be found in our
                        [API Documentation](https://pangea.cloud/docs/api/authn#update-user).

                Examples:
                    response = authn.user.profile.update(
                        profile={
                            "phone": "18085550173",
                        },
                        email: "joe.user@email.com",
                    )
                """
                input = m.UserProfileUpdateRequest(
                    id=id,
                    email=email,
                    profile=profile,
                )
                response = self.request.post("v1/user/profile/update", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserProfileUpdateResult(**response.raw_result)
                return response

        class Invites(ServiceBase):
            service_name = SERVICE_NAME
            _support_multi_config = SUPPORT_MULTI_CONFIG

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            # https://pangea.cloud/docs/api/authn#list-invites
            # - path: authn::/v1/user/invite/list
            def list(
                self,
                filter: Optional[Dict] = None,
                last: Optional[str] = None,
                order: Optional[m.ItemOrder] = None,
                order_by: Optional[m.UserInviterOrderBy] = None,
                size: Optional[int] = None,
            ) -> PangeaResponse[m.UserInviteListResult]:
                """
                List Invites

                Look up active invites for the userpool.

                OperationId: authn_post_v1_user_invite_list

                Args:
                    filter (dict, optional):
                    last (str, optional): Reflected value from a previous response to obtain the next page of results.
                    order (m.ItemOrder, optional): Order results asc(ending) or desc(ending).
                    order_by (m.UserInviterOrderBy, optional): Which field to order results by.
                    size (int, optional): Maximum results to include in the response. Minimum: 1.

                Returns:
                    A PangeaResponse with a list of pending user invitations in the response.result field.
                        Available response fields can be found in our
                        [API Documentation](https://pangea.cloud/docs/api/authn#list-invites).

                Examples:
                    response = authn.user.invites.list()
                """
                input = m.UserInviteListRequest(filter=filter, last=last, order=order, order_by=order_by, size=size)
                response = self.request.post("v1/user/invite/list", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserInviteListResult(**response.raw_result)
                return response

            # https://pangea.cloud/docs/api/authn#delete-invite
            # - path: authn::/v1/user/invite/delete
            def delete(self, id: str) -> PangeaResponse[m.UserInviteDeleteResult]:
                """
                Delete Invite

                Delete a user invitation.

                OperationId: authn_post_v1_user_invite_delete

                Args:
                    id (str): A one-time ticket

                Returns:
                    A PangeaResponse with an empty object in the response.result field.

                Examples:
                    authn.user.invites.delete(
                        id="pmc_wuk7tvtpswyjtlsx52b7yyi2l7zotv4a",
                    )
                """
                input = m.UserInviteDeleteRequest(id=id)
                response = self.request.post("v1/user/invite/delete", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.UserInviteDeleteResult(**response.raw_result)
                return response

    class Flow(ServiceBase):
        service_name = SERVICE_NAME
        _support_multi_config = SUPPORT_MULTI_CONFIG

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
            response = self.request.post("v1/flow/complete", data=input.dict(exclude_none=True))
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
            response = self.request.post("v1/flow/start", data=input.dict(exclude_none=True))
            if response.raw_result is not None:
                response.result = m.FlowStartResult(**response.raw_result)
            return response

        class Reset(ServiceBase):
            service_name = SERVICE_NAME
            _support_multi_config = SUPPORT_MULTI_CONFIG

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
                response = self.request.post("v1/flow/reset/password", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.FlowResetPasswordResult(**response.raw_result)
                return response

        class Enroll(ServiceBase):
            service_name = SERVICE_NAME
            _support_multi_config = SUPPORT_MULTI_CONFIG

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)
                self.mfa = AuthN.Flow.Enroll.MFA(token, config, logger_name=logger_name)

            class MFA(ServiceBase):
                service_name = SERVICE_NAME
                _support_multi_config = SUPPORT_MULTI_CONFIG

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
                    response = self.request.post("v1/flow/enroll/mfa/complete", data=input.dict(exclude_none=True))
                    if response.raw_result is not None:
                        response.result = m.FlowEnrollMFAcompleteResult(**response.raw_result)
                    return response

                #   - path: authn::/v1/flow/enroll/mfa/start
                # https://dev.pangea.cloud/docs/api/authn#start-the-process-of-enrolling-an-mfa
                def start(
                    self, flow_id: str, mfa_provider: m.MFAProvider, phone: Optional[str] = None
                ) -> PangeaResponse[m.FlowEnrollMFAStartResult]:
                    input = m.FlowEnrollMFAStartRequest(flow_id=flow_id, mfa_provider=mfa_provider, phone=phone)
                    response = self.request.post("v1/flow/enroll/mfa/start", data=input.dict(exclude_none=True))
                    if response.raw_result is not None:
                        response.result = m.FlowEnrollMFAStartResult(**response.raw_result)
                    return response

        class Signup(ServiceBase):
            service_name = SERVICE_NAME
            _support_multi_config = SUPPORT_MULTI_CONFIG

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
                response = self.request.post("v1/flow/signup/password", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.FlowSignupPasswordResult(**response.raw_result)
                return response

            #   - path: authn::/v1/flow/signup/social
            # https://dev.pangea.cloud/docs/api/authn#signup-a-new-account-using-a-social-provider
            def social(self, flow_id: str, cb_state: str, cb_code: str) -> PangeaResponse[m.FlowSignupSocialResult]:
                input = m.FlowSignupSocialRequest(flow_id=flow_id, cb_state=cb_state, cb_code=cb_code)
                response = self.request.post("v1/flow/signup/social", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.FlowSignupSocialResult(**response.raw_result)
                return response

        class Verify(ServiceBase):
            service_name = SERVICE_NAME
            _support_multi_config = SUPPORT_MULTI_CONFIG

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
                response = self.request.post("v1/flow/verify/captcha", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.FlowVerifyCaptchaResult(**response.raw_result)
                return response

            #   - path: authn::/v1/flow/verify/email
            # https://dev.pangea.cloud/docs/api/authn#verify-an-email-address-during-a-signup-or-signin-flow
            def email(
                self, flow_id: str, cb_state: Optional[str] = None, cb_code: Optional[str] = None
            ) -> PangeaResponse[m.FlowVerifyEmailResult]:
                input = m.FlowVerifyEmailRequest(flow_id=flow_id, cb_state=cb_state, cb_code=cb_code)
                response = self.request.post("v1/flow/verify/email", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.FlowVerifyEmailResult(**response.raw_result)
                return response

            #   - path: authn::/v1/flow/verify/password
            # https://dev.pangea.cloud/docs/api/authn#sign-in-with-a-password
            def password(
                self, flow_id: str, password: Optional[str] = None, cancel: Optional[bool] = None
            ) -> PangeaResponse[m.FlowVerifyPasswordResult]:
                input = m.FlowVerifyPasswordRequest(flow_id=flow_id, password=password, cancel=cancel)
                response = self.request.post("v1/flow/verify/password", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.FlowVerifyPasswordResult(**response.raw_result)
                return response

            #   - path: authn::/v1/flow/verify/social
            # https://dev.pangea.cloud/docs/api/authn#signin-with-a-social-provider
            def social(self, flow_id: str, cb_state: str, cb_code: str) -> PangeaResponse[m.FlowVerifySocialResult]:
                input = m.FlowVerifySocialRequest(flow_id=flow_id, cb_state=cb_state, cb_code=cb_code)
                response = self.request.post("v1/flow/verify/social", data=input.dict(exclude_none=True))
                if response.raw_result is not None:
                    response.result = m.FlowVerifySocialResult(**response.raw_result)
                return response

            class MFA(ServiceBase):
                service_name = SERVICE_NAME
                _support_multi_config = SUPPORT_MULTI_CONFIG

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
                    response = self.request.post("v1/flow/verify/mfa/complete", data=input.dict(exclude_none=True))
                    if response.raw_result is not None:
                        response.result = m.FlowVerifyMFACompleteResult(**response.raw_result)
                    return response

                #   - path: authn::/v1/flow/verify/mfa/start
                # https://dev.pangea.cloud/docs/api/authn#start-the-process-of-mfa-verification
                def start(
                    self, flow_id: str, mfa_provider: m.MFAProvider
                ) -> PangeaResponse[m.FlowVerifyMFAStartResult]:
                    input = m.FlowVerifyMFAStartRequest(flow_id=flow_id, mfa_provider=mfa_provider)
                    response = self.request.post("v1/flow/verify/mfa/start", data=input.dict(exclude_none=True))
                    if response.raw_result is not None:
                        response.result = m.FlowVerifyMFAStartResult(**response.raw_result)
                    return response

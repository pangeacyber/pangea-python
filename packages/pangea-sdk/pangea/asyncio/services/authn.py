# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from typing import Dict, List, Optional, Union

import pangea.services.authn.models as m
from pangea.response import PangeaResponse

from .base import ServiceBaseAsync

SERVICE_NAME = "authn"


class AuthNAsync(ServiceBaseAsync):
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

    def __init__(
        self,
        token,
        config=None,
        logger_name="pangea",
    ):
        super().__init__(token, config, logger_name=logger_name)
        self.user = AuthNAsync.User(token, config, logger_name=logger_name)
        self.flow = AuthNAsync.Flow(token, config, logger_name=logger_name)
        self.client = AuthNAsync.Client(token, config, logger_name=logger_name)
        self.session = AuthNAsync.Session(token, config, logger_name=logger_name)
        self.agreements = AuthNAsync.Agreements(token, config, logger_name=logger_name)

    class Session(ServiceBaseAsync):
        service_name = SERVICE_NAME

        def __init__(
            self,
            token,
            config=None,
            logger_name="pangea",
        ):
            super().__init__(token, config, logger_name=logger_name)

        # https://pangea.cloud/docs/api/authn#invalidate-session
        # - path: authn::/v1/session/invalidate
        async def invalidate(self, session_id: str) -> PangeaResponse[m.SessionInvalidateResult]:
            """
            Invalidate Session

            Invalidate a session by session ID.

            OperationId: authn_post_v1_session_invalidate

            Args:
                session_id (str): An ID for a session

            Returns:
                A PangeaResponse with an empty object in the response.result field.

            Examples:
                authn.session.invalidate(
                    session_id="pmt_zppkzrjguxyblaia6itbiesejn7jejnr",
                )
            """
            input = m.SessionInvalidateRequest(session_id=session_id)
            return await self.request.post(
                "v1/session/invalidate", m.SessionInvalidateResult, data=input.dict(exclude_none=True)
            )

        # https://pangea.cloud/docs/api/authn#list-session-service-token
        # - path: authn::/v1/session/list
        async def list(
            self,
            filter: Optional[Union[Dict, m.SessionListFilter]] = None,
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
                response = await authn.session.list()
            """
            input = m.SessionListRequest(filter=filter, last=last, order=order, order_by=order_by, size=size)
            return await self.request.post("v1/session/list", m.SessionListResults, data=input.dict(exclude_none=True))

        # https://pangea.cloud/docs/api/authn#log-out-service-token
        # - path: authn::/v1/session/logout
        async def logout(self, user_id: str) -> PangeaResponse[m.SessionLogoutResult]:
            """
            Log out (service token)

            Invalidate all sessions belonging to a user.

            OperationId: authn_post_v1_session_logout

            Args:
                user_id (str): The id of a user.

            Returns:
                A PangeaResponse with an empty object in the response.result field.

            Examples:
                authn.session.logout(
                    user_id="pui_xpkhwpnz2cmegsws737xbsqnmnuwtvm5",
                )
            """
            input = m.SessionLogoutRequest(user_id=user_id)
            return await self.request.post(
                "v1/session/logout", m.SessionLogoutResult, data=input.dict(exclude_none=True)
            )

    class Client(ServiceBaseAsync):
        service_name = SERVICE_NAME

        def __init__(
            self,
            token,
            config=None,
            logger_name="pangea",
        ):
            super().__init__(token, config, logger_name=logger_name)
            self.session = AuthNAsync.Client.Session(token, config, logger_name=logger_name)
            self.password = AuthNAsync.Client.Password(token, config, logger_name=logger_name)
            self.token_endpoints = AuthNAsync.Client.Token(token, config, logger_name=logger_name)

        # https://pangea.cloud/docs/api/authn#get-user-client-token
        # - path: authn::/v1/client/userinfo
        async def userinfo(self, code: str) -> PangeaResponse[m.ClientUserinfoResult]:
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
                response = await authn.client.userinfo(
                    code="pmc_d6chl6qulpn3it34oerwm3cqwsjd6dxw",
                )
            """
            input = m.ClientUserinfoRequest(code=code)
            return await self.request.post(
                "v1/client/userinfo", m.ClientUserinfoResult, data=input.dict(exclude_none=True)
            )

        # https://pangea.cloud/docs/api/authn#get-jwt-verification-keys
        # - path: authn::/v1/client/jwks
        async def jwks(
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
                response = await authn.client.jwks()
            """
            return await self.request.post("v1/client/jwks", m.ClientJWKSResult, {})

        class Session(ServiceBaseAsync):
            service_name = SERVICE_NAME

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            # https://pangea.cloud/docs/api/authn#invalidate-session-client
            # - path: authn::/v1/client/session/invalidate
            async def invalidate(self, token: str, session_id: str) -> PangeaResponse[m.ClientSessionInvalidateResult]:
                """
                Invalidate Session | Client

                Invalidate a session by session ID using a client token.

                OperationId: authn_post_v1_client_session_invalidate

                Args:
                    token (str): A user token value
                    session_id (str): An ID for a session

                Returns:
                    A PangeaResponse with an empty object in the response.result field.

                Examples:
                    authn.client.session.invalidate(
                        token="ptu_wuk7tvtpswyjtlsx52b7yyi2l7zotv4a",
                        session_id="pmt_zppkzrjguxyblaia6itbiesejn7jejnr",
                    )
                """
                input = m.ClientSessionInvalidateRequest(token=token, session_id=session_id)
                return await self.request.post(
                    "v1/client/session/invalidate", m.ClientSessionInvalidateResult, data=input.dict(exclude_none=True)
                )

            # https://pangea.cloud/docs/api/authn#list-sessions-client-token
            # - path: authn::/v1/client/session/list
            async def list(
                self,
                token: str,
                filter: Optional[Union[Dict, m.SessionListFilter]] = None,
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
                    response = await authn.client.session.list(
                        token="ptu_wuk7tvtpswyjtlsx52b7yyi2l7zotv4a",
                    )
                """
                input = m.ClientSessionListRequest(
                    token=token, filter=filter, last=last, order=order, order_by=order_by, size=size
                )
                return await self.request.post(
                    "v1/client/session/list", m.ClientSessionListResults, data=input.dict(exclude_none=True)
                )

            # https://pangea.cloud/docs/api/authn#log-out-client-token
            # - path: authn::/v1/client/session/logout
            async def logout(self, token: str) -> PangeaResponse[m.ClientSessionLogoutResult]:
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
                return await self.request.post(
                    "v1/client/session/logout", m.ClientSessionLogoutResult, data=input.dict(exclude_none=True)
                )

            # https://pangea.cloud/docs/api/authn#refresh-a-session
            # - path: authn::/v1/client/session/refresh
            async def refresh(
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
                    response = await authn.client.session.refresh(
                        refresh_token="ptr_xpkhwpnz2cmegsws737xbsqnmnuwtbm5",
                        user_token="ptu_wuk7tvtpswyjtlsx52b7yyi2l7zotv4a",
                    )
                """
                input = m.ClientSessionRefreshRequest(refresh_token=refresh_token, user_token=user_token)
                return await self.request.post(
                    "v1/client/session/refresh", m.ClientSessionRefreshResult, data=input.dict(exclude_none=True)
                )

        class Password(ServiceBaseAsync):
            service_name = SERVICE_NAME

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            # https://pangea.cloud/docs/api/authn#change-a-users-password
            # - path: authn::/v1/client/password/change
            async def change(
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
                return await self.request.post(
                    "v1/client/password/change", m.ClientPasswordChangeResult, data=input.dict(exclude_none=True)
                )

        class Token(ServiceBaseAsync):
            service_name = SERVICE_NAME

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            async def check(self, token: str) -> PangeaResponse[m.ClientTokenCheckResult]:
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
                    response = await authn.client.token_endpoints.check(
                        token="ptu_wuk7tvtpswyjtlsx52b7yyi2l7zotv4a",
                    )
                """
                input = m.ClientTokenCheckRequest(token=token)
                return await self.request.post(
                    "v1/client/token/check", m.ClientTokenCheckResult, data=input.dict(exclude_none=True)
                )

    class User(ServiceBaseAsync):
        service_name = SERVICE_NAME

        def __init__(
            self,
            token,
            config=None,
            logger_name="pangea",
        ):
            super().__init__(token, config, logger_name=logger_name)
            self.profile = AuthNAsync.User.Profile(token, config, logger_name=logger_name)
            self.invites = AuthNAsync.User.Invites(token, config, logger_name=logger_name)
            self.mfa = AuthNAsync.User.MFA(token, config, logger_name=logger_name)
            self.login = AuthNAsync.User.Login(token, config, logger_name=logger_name)
            self.password = AuthNAsync.User.Password(token, config, logger_name=logger_name)

        # https://pangea.cloud/docs/api/authn#create-user
        # - path: authn::/v1/user/create
        async def create(
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
                response = await authn.user.create(
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
            return await self.request.post("v1/user/create", m.UserCreateResult, data=input.dict(exclude_none=True))

        # https://pangea.cloud/docs/api/authn#delete-user
        # - path: authn::/v1/user/delete
        async def delete(
            self, email: Optional[str] = None, id: Optional[str] = None
        ) -> PangeaResponse[m.UserDeleteResult]:
            """
            Delete User

            Delete a user.

            OperationId: authn_post_v1_user_delete

            Args:
                email (str, optional): An email address
                id (str, optional): The id of a user or a service

            Returns:
                A PangeaResponse with an empty object in the response.result field.

            Examples:
                authn.user.delete(email="example@example.com")
            """
            input = m.UserDeleteRequest(email=email, id=id)
            return await self.request.post("v1/user/delete", m.UserDeleteResult, data=input.dict(exclude_none=True))

        # https://pangea.cloud/docs/api/authn#update-users-settings
        # - path: authn::/v1/user/update
        async def update(
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
                response = await authn.user.update(
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

            return await self.request.post("v1/user/update", m.UserUpdateResult, data=input.dict(exclude_none=True))

        # https://pangea.cloud/docs/api/authn#invite-user
        # - path: authn::/v1/user/invite
        async def invite(
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
                response = await authn.user.invite(
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
            return await self.request.post("v1/user/invite", m.UserInviteResult, data=input.dict(exclude_none=True))

        # https://pangea.cloud/docs/api/authn#list-users
        # - path: authn::/v1/user/list
        async def list(
            self,
            filter: Optional[Union[Dict, m.UserListFilter]] = None,
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
                response = await authn.user.list()
            """
            input = m.UserListRequest(
                filter=filter,
                last=last,
                order=order,
                order_by=order_by,
                size=size,
            )
            return await self.request.post("v1/user/list", m.UserListResult, data=input.dict(exclude_none=True))

        # https://pangea.cloud/docs/api/authn#verify-user
        # - path: authn::/v1/user/verify
        async def verify(
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
                response = await authn.user.verify(
                    id_provider=IDProvider.PASSWORD,
                    email="joe.user@email.com",
                    authenticator="My1s+Password",
                )
            """
            input = m.UserVerifyRequest(id_provider=id_provider, email=email, authenticator=authenticator)
            return await self.request.post("v1/user/verify", m.UserVerifyResult, data=input.dict(exclude_none=True))

        class Password(ServiceBaseAsync):
            service_name = SERVICE_NAME

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            # https://pangea.cloud/docs/api/authn#user-password-reset
            # - path: authn::/v1/user/password/reset
            async def reset(self, user_id: str, new_password: str) -> PangeaResponse[m.UserPasswordResetResult]:
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
                    response = await authn.user.password.reset(
                      user_id="pui_xpkhwpnz2cmegsws737xbsqnmnuwtvm5",
                    )
                """
                input = m.UserPasswordResetRequest(user_id=user_id, new_password=new_password)
                return await self.request.post(
                    "v1/user/password/reset", m.UserPasswordResetResult, data=input.dict(exclude_none=True)
                )

        class Login(ServiceBaseAsync):
            service_name = SERVICE_NAME

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            # https://pangea.cloud/docs/api/authn#login-with-a-password
            # - path: authn::/v1/user/login/password
            async def password(
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
                    response = await authn.user.login.password(
                        email="joe.user@email.com",
                        password="My1s+Password",
                        extra_profile={
                            "first_name": "Joe",
                            "last_name": "User",
                        },
                    )
                """
                input = m.UserLoginPasswordRequest(email=email, password=password, extra_profile=extra_profile)
                return await self.request.post(
                    "v1/user/login/password", m.UserLoginResult, data=input.dict(exclude_none=True)
                )

            # https://pangea.cloud/docs/api/authn#login-with-a-social-provider
            # - path: authn::/v1/user/login/social
            async def social(
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
                    response = await authn.user.login.social(
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
                return await self.request.post(
                    "v1/user/login/social", m.UserLoginResult, data=input.dict(exclude_none=True)
                )

        class MFA(ServiceBaseAsync):
            service_name = SERVICE_NAME

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            # https://pangea.cloud/docs/api/authn#delete-mfa-enrollment
            # - path: authn::/v1/user/mfa/delete
            async def delete(self, user_id: str, mfa_provider: m.MFAProvider) -> PangeaResponse[m.UserMFADeleteResult]:
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
                return await self.request.post(
                    "v1/user/mfa/delete", m.UserMFADeleteResult, data=input.dict(exclude_none=True)
                )

            # https://pangea.cloud/docs/api/authn#enroll-in-mfa
            # - path: authn::/v1/user/mfa/enroll
            async def enroll(
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
                return await self.request.post(
                    "v1/user/mfa/enroll", m.UserMFAEnrollResult, data=input.dict(exclude_none=True)
                )

            # https://pangea.cloud/docs/api/authn#user-start-mfa-verification
            # - path: authn::/v1/user/mfa/start
            async def start(
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
                    response = await authn.user.mfa.start(
                        user_id="pui_zgp532cx6opljeavvllmbi3iwmq72f7f",
                        mfa_provider=MFAProvider.SMS_OTP,
                        phone="1-808-555-0173",
                    )
                """
                input = m.UserMFAStartRequest(user_id=user_id, mfa_provider=mfa_provider, enroll=enroll, phone=phone)
                return await self.request.post(
                    "v1/user/mfa/start", m.UserMFAStartResult, data=input.dict(exclude_none=True)
                )

            # https://pangea.cloud/docs/api/authn#verify-an-mfa-code
            # - path: authn::/v1/user/mfa/verify
            async def verify(
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
                return await self.request.post(
                    "v1/user/mfa/verify", m.UserMFAVerifyResult, data=input.dict(exclude_none=True)
                )

        class Profile(ServiceBaseAsync):
            service_name = SERVICE_NAME

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            # https://pangea.cloud/docs/api/authn#get-user
            # - path: authn::/v1/user/profile/get
            async def get(
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
                    response = await authn.user.profile.get(
                        email="joe.user@email.com",
                    )
                """
                input = m.UserProfileGetRequest(id=id, email=email)
                return await self.request.post(
                    "v1/user/profile/get", m.UserProfileGetResult, data=input.dict(exclude_none=True)
                )

            # https://pangea.cloud/docs/api/authn#update-user
            # - path: authn::/v1/user/profile/update
            async def update(
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
                    response = await authn.user.profile.update(
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
                return await self.request.post(
                    "v1/user/profile/update", m.UserProfileUpdateResult, data=input.dict(exclude_none=True)
                )

        class Invites(ServiceBaseAsync):
            service_name = SERVICE_NAME

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            # https://pangea.cloud/docs/api/authn#list-invites
            # - path: authn::/v1/user/invite/list
            async def list(
                self,
                filter: Optional[Union[Dict, m.UserInviteListFilter]] = None,
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
                    response = await authn.user.invites.list()
                """
                input = m.UserInviteListRequest(filter=filter, last=last, order=order, order_by=order_by, size=size)
                return await self.request.post(
                    "v1/user/invite/list", m.UserInviteListResult, data=input.dict(exclude_none=True)
                )

            # https://pangea.cloud/docs/api/authn#delete-invite
            # - path: authn::/v1/user/invite/delete
            async def delete(self, id: str) -> PangeaResponse[m.UserInviteDeleteResult]:
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
                return await self.request.post(
                    "v1/user/invite/delete", m.UserInviteDeleteResult, data=input.dict(exclude_none=True)
                )

    class Flow(ServiceBaseAsync):
        service_name = SERVICE_NAME

        def __init__(
            self,
            token,
            config=None,
            logger_name="pangea",
        ):
            super().__init__(token, config, logger_name=logger_name)
            self.enroll = AuthNAsync.Flow.Enroll(token, config, logger_name=logger_name)
            self.signup = AuthNAsync.Flow.Signup(token, config, logger_name=logger_name)
            self.verify = AuthNAsync.Flow.Verify(token, config, logger_name=logger_name)
            self.reset = AuthNAsync.Flow.Reset(token, config, logger_name=logger_name)

        # https://pangea.cloud/docs/api/authn#complete-sign-up-in
        # - path: authn::/v1/flow/complete
        async def complete(self, flow_id: str) -> PangeaResponse[m.FlowCompleteResult]:
            """
            Complete Sign-up/in

            Complete a login or signup flow.

            OperationId: authn_post_v1_flow_complete

            Args:
                flow_id (str): An ID for a login or signup flow

            Returns:
                A PangeaResponse with credentials for a login session in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn#complete-sign-up-in).

            Examples:
                response = await authn.flow.complete(
                    flow_id="pfl_dxiqyuq7ndc5ycjwdgmguwuodizcaqhh",
                )
            """
            input = m.FlowCompleteRequest(flow_id=flow_id)
            return await self.request.post("v1/flow/complete", m.FlowCompleteResult, data=input.dict(exclude_none=True))

        # https://pangea.cloud/docs/api/authn#start-a-sign-up-in
        # - path: authn::/v1/flow/start
        async def start(
            self,
            cb_uri: Optional[str] = None,
            email: Optional[str] = None,
            flow_types: Optional[List[m.FlowType]] = None,
            provider: Optional[m.IDProvider] = None,
            invitation: Optional[str] = None,
        ) -> PangeaResponse[m.FlowStartResult]:
            """
            Start a sign-up/in

            Start a new signup or signin flow.

            OperationId: authn_post_v1_flow_start

            Args:
                cb_uri (str, optional): A login callback URI
                email (str, optional): An email address
                flow_types (List[m.FlowType], optional): A list of flow types
                provider (m.IDProvider, optional): Mechanism for authenticating a user's identity
                invitation (str, optional): A one-time ticket

            Returns:
                A PangeaResponse with information about next steps needed
                    to complete a flow in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn#start-a-sign-up-in).

            Examples:
                response = await authn.flow.start(
                    cb_uri="https://www.myserver.com/callback",
                    email="joe.user@email.com",
                    flow_types=[
                        FlowType.SIGNUP,
                        FlowType.SIGNIN,
                    ],
                    provider=IDProvider.PASSWORD,
                )
            """
            input = m.FlowStartRequest(
                cb_uri=cb_uri, email=email, flow_types=flow_types, provider=provider, invitation=invitation
            )
            return await self.request.post("v1/flow/start", m.FlowStartResult, data=input.dict(exclude_none=True))

        class Reset(ServiceBaseAsync):
            service_name = SERVICE_NAME

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            # https://pangea.cloud/docs/api/authn#password-reset
            # - path: authn::/v1/flow/reset/password
            async def password(
                self,
                flow_id: str,
                password: Optional[str] = None,
                cancel: Optional[bool] = None,
            ) -> PangeaResponse[m.FlowResetPasswordResult]:
                """
                Password Reset

                Reset password during sign-in.

                OperationId: authn_post_v1_flow_reset_password

                Args:
                    flow_id (str): An ID for a login or signup flow
                    password (str): A password
                    cancel (bool, optional):

                Returns:
                    A PangeaResponse with information about next steps needed
                        to complete a flow in the response.result field.
                        Available response fields can be found in our
                        [API Documentation](https://pangea.cloud/docs/api/authn#password-reset).

                Examples:
                    response = await authn.flow.reset.password(
                        flow_id="pfl_dxiqyuq7ndc5ycjwdgmguwuodizcaqhh",
                        password="My1s+Password",
                    )
                """
                input = m.FlowResetPasswordRequest(flow_id=flow_id, password=password, cancel=cancel)
                return await self.request.post(
                    "v1/flow/reset/password", m.FlowResetPasswordResult, data=input.dict(exclude_none=True)
                )

        class Enroll(ServiceBaseAsync):
            service_name = SERVICE_NAME

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)
                self.mfa = AuthNAsync.Flow.Enroll.MFA(token, config, logger_name=logger_name)

            class MFA(ServiceBaseAsync):
                service_name = SERVICE_NAME

                def __init__(
                    self,
                    token,
                    config=None,
                    logger_name="pangea",
                ):
                    super().__init__(token, config, logger_name=logger_name)

                # https://pangea.cloud/docs/api/authn#complete-mfa-enrollment
                # - path: authn::/v1/flow/enroll/mfa/complete
                async def complete(
                    self, flow_id: str, code: Optional[str] = None, cancel: Optional[bool] = None
                ) -> PangeaResponse[m.FlowEnrollMFAcompleteResult]:
                    """
                    Complete MFA Enrollment

                    Complete MFA enrollment by verifying a trial MFA code.

                    OperationId: authn_post_v1_flow_enroll_mfa_complete

                    Args:
                        flow_id (str): An ID for a login or signup flow
                        code (str, optional): A six digit MFA code
                        cancel (bool, optional):

                    Returns:
                        A PangeaResponse with information about next steps needed
                            to complete a flow in the response.result field.
                            Available response fields can be found in our
                            [API Documentation](https://pangea.cloud/docs/api/authn#complete-mfa-enrollment).

                    Examples:
                        response = await authn.flow.enroll.mfa.complete(
                            flow_id="pfl_dxiqyuq7ndc5ycjwdgmguwuodizcaqhh",
                            code="999999",
                        )
                    """
                    input = m.FlowEnrollMFACompleteRequest(flow_id=flow_id, code=code, cancel=cancel)
                    return await self.request.post(
                        "v1/flow/enroll/mfa/complete", m.FlowEnrollMFAcompleteResult, data=input.dict(exclude_none=True)
                    )

                # https://pangea.cloud/docs/api/authn#start-mfa-enrollment
                # - path: authn::/v1/flow/enroll/mfa/start
                async def start(
                    self, flow_id: str, mfa_provider: m.MFAProvider, phone: Optional[str] = None
                ) -> PangeaResponse[m.FlowEnrollMFAStartResult]:
                    """
                    Start MFA Enrollment

                    Start the process of enrolling an MFA.

                    OperationId: authn_post_v1_flow_enroll_mfa_start

                    Args:
                        flow_id (str): An ID for a login or signup flow
                        mfa_provider (m.MFAProvider): Additional mechanism for authenticating a user's identity
                        phone (str, optional): A phone number

                    Returns:
                        A PangeaResponse with information about next steps needed
                            to complete a flow in the response.result field.
                            Available response fields can be found in our
                            [API Documentation](https://pangea.cloud/docs/api/authn#start-mfa-enrollment).

                    Examples:
                        response = await authn.flow.enroll.mfa.start(
                            flow_id="pfl_dxiqyuq7ndc5ycjwdgmguwuodizcaqhh",
                            mfa_provider=MFAProvider.SMS_OTP,
                            phone="1-808-555-0173",
                        )
                    """
                    input = m.FlowEnrollMFAStartRequest(flow_id=flow_id, mfa_provider=mfa_provider, phone=phone)
                    return await self.request.post(
                        "v1/flow/enroll/mfa/start", m.FlowEnrollMFAStartResult, data=input.dict(exclude_none=True)
                    )

        class Signup(ServiceBaseAsync):
            service_name = SERVICE_NAME

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            # https://pangea.cloud/docs/api/authn#password-sign-up
            # - path: authn::/v1/flow/signup/password
            async def password(
                self, flow_id: str, password: str, first_name: str, last_name: str
            ) -> PangeaResponse[m.FlowSignupPasswordResult]:
                """
                Password Sign-up

                Signup a new account using a password.

                OperationId: authn_post_v1_flow_signup_password

                Args:
                    flow_id (str): An ID for a login or signup flow
                    password (str): A password
                    first_name (str):
                    last_name (str):

                Returns:
                    A PangeaResponse with information about next steps needed
                        to complete a flow in the response.result field.
                        Available response fields can be found in our
                        [API Documentation](https://pangea.cloud/docs/api/authn#password-sign-up).

                Examples:
                    response = await authn.flow.signup.password(
                        flow_id="pfl_dxiqyuq7ndc5ycjwdgmguwuodizcaqhh",
                        password="My1s+Password",
                        first_name="Joe",
                        last_name="User",
                    )
                """
                input = m.FlowSignupPasswordRequest(
                    flow_id=flow_id, password=password, first_name=first_name, last_name=last_name
                )
                return await self.request.post(
                    "v1/flow/signup/password", m.FlowSignupPasswordResult, data=input.dict(exclude_none=True)
                )

            # https://pangea.cloud/docs/api/authn#social-sign-up
            # - path: authn::/v1/flow/signup/social
            async def social(
                self, flow_id: str, cb_state: str, cb_code: str
            ) -> PangeaResponse[m.FlowSignupSocialResult]:
                """
                Social Sign-up

                Signup a new account using a social provider.

                OperationId: authn_post_v1_flow_signup_social

                Args:
                    flow_id (str): An ID for a login or signup flow
                    cb_state (str): State tracking string for login callbacks
                    cb_code (str): A social oauth callback code

                Returns:
                    A PangeaResponse with information about next steps needed
                        to complete a flow in the response.result field.
                        Available response fields can be found in our
                        [API Documentation](https://pangea.cloud/docs/api/authn#social-sign-up).

                Examples:
                    response = await authn.flow.signup.social(
                        flow_id="pfl_dxiqyuq7ndc5ycjwdgmguwuodizcaqhh",
                        cb_state="pcb_zurr3lkcwdp5keq73htsfpcii5k4zgm7",
                        cb_code="poc_fwg3ul4db1jpivexru3wyj354u9ej5e2",
                    )
                """
                input = m.FlowSignupSocialRequest(flow_id=flow_id, cb_state=cb_state, cb_code=cb_code)
                return await self.request.post(
                    "v1/flow/signup/social", m.FlowSignupSocialResult, data=input.dict(exclude_none=True)
                )

        class Verify(ServiceBaseAsync):
            service_name = SERVICE_NAME

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)
                self.mfa = AuthNAsync.Flow.Verify.MFA(token, config, logger_name=logger_name)

            # https://pangea.cloud/docs/api/authn#verify-captcha
            # - path: authn::/v1/flow/verify/captcha
            async def captcha(self, flow_id: str, code: str) -> PangeaResponse[m.FlowVerifyCaptchaResult]:
                """
                Verify Captcha

                Verify a CAPTCHA during a signup or signin flow.

                OperationId: authn_post_v1_flow_verify_captcha

                Args:
                    flow_id (str): An ID for a login or signup flow
                    code (str): CAPTCHA verification code

                Returns:
                    A PangeaResponse with information about next steps needed
                        to complete a flow in the response.result field.
                        Available response fields can be found in our
                        [API Documentation](https://pangea.cloud/docs/api/authn#verify-captcha).

                Examples:
                    response = await authn.flow.verify.captcha(
                        flow_id="pfl_dxiqyuq7ndc5ycjwdgmguwuodizcaqhh",
                        code="SOMEREALLYLONGANDOPAQUESTRINGFROMCAPTCHAVERIFICATION",
                    )
                """
                input = m.FlowVerifyCaptchaRequest(flow_id=flow_id, code=code)
                return await self.request.post(
                    "v1/flow/verify/captcha", m.FlowVerifyCaptchaResult, data=input.dict(exclude_none=True)
                )

            # https://pangea.cloud/docs/api/authn#verify-email-address
            # - path: authn::/v1/flow/verify/email
            async def email(
                self, flow_id: str, cb_state: Optional[str] = None, cb_code: Optional[str] = None
            ) -> PangeaResponse[m.FlowVerifyEmailResult]:
                """
                Verify Email Address

                Verify an email address during a signup or signin flow.

                OperationId: authn_post_v1_flow_verify_email

                Args:
                    flow_id (str): An ID for a login or signup flow
                    cb_state (str, optional): State tracking string for login callbacks
                    cb_code (str, optional): A social oauth callback code

                Returns:
                    A PangeaResponse with information about next steps needed
                        to complete a flow in the response.result field.
                        Available response fields can be found in our
                        [API Documentation](https://pangea.cloud/docs/api/authn#verify-email-address).

                Examples:
                    response = await authn.flow.verify.email(
                        flow_id="pfl_dxiqyuq7ndc5ycjwdgmguwuodizcaqhh",
                        cb_state="pcb_zurr3lkcwdp5keq73htsfpcii5k4zgm7",
                        cb_code="poc_fwg3ul4db1jpivexru3wyj354u9ej5e2",
                    )
                """
                input = m.FlowVerifyEmailRequest(flow_id=flow_id, cb_state=cb_state, cb_code=cb_code)
                return await self.request.post(
                    "v1/flow/verify/email", m.FlowVerifyEmailResult, data=input.dict(exclude_none=True)
                )

            # https://pangea.cloud/docs/api/authn#password-sign-in
            # - path: authn::/v1/flow/verify/password
            async def password(
                self, flow_id: str, password: Optional[str] = None, cancel: Optional[bool] = None
            ) -> PangeaResponse[m.FlowVerifyPasswordResult]:
                """
                Password Sign-in

                Sign in with a password.

                OperationId: authn_post_v1_flow_verify_password

                Args:
                    flow_id (str): An ID for a login or signup flow
                    password (str, optional): A password
                    cancel (bool, optional):

                Returns:
                    A PangeaResponse with information about next steps needed
                        to complete a flow in the response.result field.
                        Available response fields can be found in our
                        [API Documentation](https://pangea.cloud/docs/api/authn#password-sign-in).

                Examples:
                    response = await authn.flow.verify.password(
                        flow_id="pfl_dxiqyuq7ndc5ycjwdgmguwuodizcaqhh",
                        password="My1s+Password",
                    )
                """
                input = m.FlowVerifyPasswordRequest(flow_id=flow_id, password=password, cancel=cancel)
                return await self.request.post(
                    "v1/flow/verify/password", m.FlowVerifyPasswordResult, data=input.dict(exclude_none=True)
                )

            # https://pangea.cloud/docs/api/authn#social-sign-in
            # - path: authn::/v1/flow/verify/social
            async def social(
                self, flow_id: str, cb_state: str, cb_code: str
            ) -> PangeaResponse[m.FlowVerifySocialResult]:
                """
                Social Sign-in

                Signin with a social provider.

                OperationId: authn_post_v1_flow_verify_social

                Args:
                    flow_id (str): An ID for a login or signup flow
                    cb_state (str): State tracking string for login callbacks
                    cb_code (str): A social oauth callback code

                Returns:
                    A PangeaResponse with information about next steps needed
                        to complete a flow in the response.result field.
                        Available response fields can be found in our
                        [API Documentation](https://pangea.cloud/docs/api/authn#social-sign-in).

                Examples:
                    response = await authn.flow.verify.social(
                        flow_id="pfl_dxiqyuq7ndc5ycjwdgmguwuodizcaqhh",
                        cb_state="pcb_zurr3lkcwdp5keq73htsfpcii5k4zgm7",
                        cb_code="poc_fwg3ul4db1jpivexru3wyj354u9ej5e2",
                    )
                """
                input = m.FlowVerifySocialRequest(flow_id=flow_id, cb_state=cb_state, cb_code=cb_code)
                return await self.request.post(
                    "v1/flow/verify/social", m.FlowVerifySocialResult, data=input.dict(exclude_none=True)
                )

            class MFA(ServiceBaseAsync):
                service_name = SERVICE_NAME

                def __init__(
                    self,
                    token,
                    config=None,
                    logger_name="pangea",
                ):
                    super().__init__(token, config, logger_name=logger_name)

                # https://pangea.cloud/docs/api/authn#complete-mfa-verification
                # - path: authn::/v1/flow/verify/mfa/complete
                async def complete(
                    self, flow_id: str, code: Optional[str] = None, cancel: Optional[bool] = None
                ) -> PangeaResponse[m.FlowVerifyMFACompleteResult]:
                    """
                    Complete MFA Verification

                    Complete MFA verification.

                    OperationId: authn_post_v1_flow_verify_mfa_complete

                    Args:
                        flow_id (str): An ID for a login or signup flow
                        code (str, optional): A six digit MFA code
                        cancel (bool, optional):

                    Returns:
                        A PangeaResponse with information about next steps needed
                            to complete a flow in the response.result field.
                            Available response fields can be found in our
                            [API Documentation](https://pangea.cloud/docs/api/authn#complete-mfa-verification).

                    Examples:
                        response = await authn.flow.verify.mfa.complete(
                            flow_id="pfl_dxiqyuq7ndc5ycjwdgmguwuodizcaqhh",
                            code="999999",
                        )
                    """
                    input = m.FlowVerifyMFACompleteRequest(flow_id=flow_id, code=code, cancel=cancel)
                    return await self.request.post(
                        "v1/flow/verify/mfa/complete", m.FlowVerifyMFACompleteResult, data=input.dict(exclude_none=True)
                    )

                # https://pangea.cloud/docs/api/authn#start-mfa-verification
                # - path: authn::/v1/flow/verify/mfa/start
                async def start(
                    self, flow_id: str, mfa_provider: m.MFAProvider
                ) -> PangeaResponse[m.FlowVerifyMFAStartResult]:
                    """
                    Start MFA Verification

                    Start the process of MFA verification.

                    OperationId: authn_post_v1_flow_verify_mfa_start

                    Args:
                        flow_id (str): An ID for a login or signup flow
                        mfa_provider (m.MFAProvider): Additional mechanism for authenticating a user's identity

                    Returns:
                        A PangeaResponse with information about next steps needed
                            to complete a flow in the response.result field.
                            Available response fields can be found in our
                            [API Documentation](https://pangea.cloud/docs/api/authn#start-mfa-verification).

                    Examples:
                        response = await authn.flow.verify.mfa.start(
                            flow_id="pfl_dxiqyuq7ndc5ycjwdgmguwuodizcaqhh",
                            mfa_provider=MFAProvider.TOTP,
                        )
                    """
                    input = m.FlowVerifyMFAStartRequest(flow_id=flow_id, mfa_provider=mfa_provider)
                    return await self.request.post(
                        "v1/flow/verify/mfa/start", m.FlowVerifyMFAStartResult, data=input.dict(exclude_none=True)
                    )

    class Agreements(ServiceBaseAsync):
        service_name = SERVICE_NAME

        def __init__(
            self,
            token,
            config=None,
            logger_name="pangea",
        ):
            super().__init__(token, config, logger_name=logger_name)

        async def create(
            self, type: m.AgreementType, name: str, text: str, active: Optional[bool] = None
        ) -> PangeaResponse[m.AgreementCreateResult]:
            input = m.AgreementCreateRequest(type=type, name=name, text=text, active=active)
            return await self.request.post(
                "v1/agreements/create", m.AgreementCreateResult, data=input.dict(exclude_none=True)
            )

        async def delete(self, type: m.AgreementType, id: str) -> PangeaResponse[m.AgreementDeleteResult]:
            input = m.AgreementDeleteRequest(type=type, id=id)
            return await self.request.post(
                "v1/agreements/delete", m.AgreementDeleteResult, data=input.dict(exclude_none=True)
            )

        async def list(
            self,
            filter: Optional[Union[Dict, m.AgreementListFilter]] = None,
            last: Optional[str] = None,
            order: Optional[m.ItemOrder] = None,
            order_by: Optional[m.AgreementListOrderBy] = None,
            size: Optional[int] = None,
        ) -> PangeaResponse[m.AgreementListResult]:
            input = m.AgreementListRequest(filter=filter, last=last, order=order, order_by=order_by, size=size)
            return await self.request.post(
                "v1/agreements/list", m.AgreementListResult, data=input.dict(exclude_none=True)
            )

        async def update(
            self,
            type: m.AgreementType,
            id: str,
            name: Optional[str] = None,
            text: Optional[str] = None,
            active: Optional[bool] = None,
        ) -> PangeaResponse[m.AgreementUpdateResult]:
            input = m.AgreementUpdateRequest(type=type, id=id, name=name, text=text, active=active)
            return await self.request.post(
                "v1/agreements/update", m.AgreementUpdateResult, data=input.dict(exclude_none=True)
            )

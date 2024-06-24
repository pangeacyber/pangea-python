# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
from __future__ import annotations

from typing import Dict, List, Optional, Union

import pangea.services.authn.models as m
from pangea.asyncio.services.base import ServiceBaseAsync
from pangea.config import PangeaConfig
from pangea.response import PangeaResponse, PangeaResponseResult

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
        from pangea.asyncio.services import AuthNAsync
        from pangea.config import PangeaConfig

        PANGEA_TOKEN = os.getenv("PANGEA_AUTHN_TOKEN")
        authn_config = PangeaConfig(domain="pangea.cloud")

        # Setup Pangea AuthN service
        authn = AuthNAsync(token=PANGEA_TOKEN, config=authn_config)
    """

    service_name = SERVICE_NAME

    def __init__(
        self,
        token: str,
        config: PangeaConfig | None = None,
        logger_name: str = "pangea",
    ) -> None:
        """
        AuthN client

        Initializes a new AuthN client.

        Args:
            token: Pangea API token.
            config: Configuration.
            logger_name: Logger name.

        Examples:
             config = PangeaConfig(domain="pangea_domain")
             authn = AuthNAsync(token="pangea_token", config=config)
        """
        super().__init__(token, config, logger_name=logger_name)
        self.user = AuthNAsync.UserAsync(token, config, logger_name=logger_name)
        self.flow = AuthNAsync.FlowAsync(token, config, logger_name=logger_name)
        self.client = AuthNAsync.ClientAsync(token, config, logger_name=logger_name)
        self.session = AuthNAsync.SessionAsync(token, config, logger_name=logger_name)
        self.agreements = AuthNAsync.AgreementsAsync(token, config, logger_name=logger_name)

    class SessionAsync(ServiceBaseAsync):
        service_name = SERVICE_NAME

        def __init__(
            self,
            token: str,
            config: PangeaConfig | None = None,
            logger_name: str = "pangea",
        ) -> None:
            super().__init__(token, config, logger_name=logger_name)

        async def invalidate(self, session_id: str) -> PangeaResponse[m.SessionInvalidateResult]:
            """
            Invalidate Session

            Invalidate a session by session ID.

            OperationId: authn_post_v2_session_invalidate

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
                "v2/session/invalidate", m.SessionInvalidateResult, data=input.model_dump(exclude_none=True)
            )

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

            OperationId: authn_post_v2_session_list

            Args:
                filter (dict, optional):
                last (str, optional): Reflected value from a previous response to obtain the next page of results.
                order (m.ItemOrder, optional): Order results asc(ending) or desc(ending).
                order_by (m.SessionListOrderBy, optional): Which field to order results by.
                size (int, optional): Maximum results to include in the response. Minimum: 1.

            Returns:
                A PangeaResponse with a list of sessions in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn/session#/v2/session/list).

            Examples:
                response = authn.session.list()
            """
            if isinstance(filter, dict):
                filter = m.SessionListFilter(**filter)

            input = m.SessionListRequest(filter=filter, last=last, order=order, order_by=order_by, size=size)
            return await self.request.post(
                "v2/session/list", m.SessionListResults, data=input.model_dump(exclude_none=True)
            )

        async def logout(self, user_id: str) -> PangeaResponse[m.SessionLogoutResult]:
            """
            Log out (service token)

            Invalidate all sessions belonging to a user.

            OperationId: authn_post_v2_session_logout

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
                "v2/session/logout", m.SessionLogoutResult, data=input.model_dump(exclude_none=True)
            )

    class ClientAsync(ServiceBaseAsync):
        service_name = SERVICE_NAME

        def __init__(
            self,
            token: str,
            config: PangeaConfig | None = None,
            logger_name: str = "pangea",
        ) -> None:
            super().__init__(token, config, logger_name=logger_name)
            self.session = AuthNAsync.ClientAsync.SessionAsync(token, config, logger_name=logger_name)
            self.password = AuthNAsync.ClientAsync.PasswordAsync(token, config, logger_name=logger_name)
            self.token_endpoints = AuthNAsync.ClientAsync.TokenAsync(token, config, logger_name=logger_name)

        async def userinfo(self, code: str) -> PangeaResponse[m.ClientUserinfoResult]:
            """
            Get User (client token)

            Retrieve the logged in user's token and information.

            OperationId: authn_post_v2_client_userinfo

            Args:
                code (str): Login code returned by the login callback

            Returns:
                A PangeaResponse with credentials for a login session in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn/user#/v2/client/userinfo).

            Examples:
                response = authn.client.userinfo(
                    code="pmc_d6chl6qulpn3it34oerwm3cqwsjd6dxw",
                )
            """
            input = m.ClientUserinfoRequest(code=code)
            return await self.request.post(
                "v2/client/userinfo", m.ClientUserinfoResult, data=input.model_dump(exclude_none=True)
            )

        async def jwks(
            self,
        ) -> PangeaResponse[m.ClientJWKSResult]:
            """
            Get JWT verification keys

            Get JWT verification keys.

            OperationId: authn_post_v2_client_jwks

            Returns:
                A PangeaResponse with jwt verification keys in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn/jwt#/v2/client/jwks).

            Examples:
                response = authn.client.jwks()
            """
            return await self.request.post("v2/client/jwks", m.ClientJWKSResult, {})

        class SessionAsync(ServiceBaseAsync):
            service_name = SERVICE_NAME

            def __init__(
                self,
                token: str,
                config: PangeaConfig | None = None,
                logger_name: str = "pangea",
            ) -> None:
                super().__init__(token, config, logger_name=logger_name)

            async def invalidate(self, token: str, session_id: str) -> PangeaResponse[m.ClientSessionInvalidateResult]:
                """
                Invalidate Session | Client

                Invalidate a session by session ID using a client token.

                OperationId: authn_post_v2_client_session_invalidate

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
                    "v2/client/session/invalidate",
                    m.ClientSessionInvalidateResult,
                    data=input.model_dump(exclude_none=True),
                )

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

                OperationId: authn_post_v2_client_session_list

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
                        [API Documentation](https://pangea.cloud/docs/api/authn/session#/v2/client/session/list).

                Examples:
                    response = authn.client.session.list(
                        token="ptu_wuk7tvtpswyjtlsx52b7yyi2l7zotv4a",
                    )
                """
                if isinstance(filter, dict):
                    filter = m.SessionListFilter(**filter)

                input = m.ClientSessionListRequest(
                    token=token, filter=filter, last=last, order=order, order_by=order_by, size=size
                )
                return await self.request.post(
                    "v2/client/session/list", m.ClientSessionListResults, data=input.model_dump(exclude_none=True)
                )

            async def logout(self, token: str) -> PangeaResponse[m.ClientSessionLogoutResult]:
                """
                Log out (client token)

                Log out the current user's session.

                OperationId: authn_post_v2_client_session_logout

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
                    "v2/client/session/logout", m.ClientSessionLogoutResult, data=input.model_dump(exclude_none=True)
                )

            async def refresh(
                self, refresh_token: str, user_token: Optional[str] = None
            ) -> PangeaResponse[m.ClientSessionRefreshResult]:
                """
                Refresh a Session

                Refresh a session token.

                OperationId: authn_post_v2_client_session_refresh

                Args:
                    refresh_token (str): A refresh token value
                    user_token (str, optional): A user token value

                Returns:
                    A PangeaResponse with credentials for a login session in the response.result field.
                        Available response fields can be found in our
                        [API Documentation](https://pangea.cloud/docs/api/authn/session#/v2/client/session/refresh).

                Examples:
                    response = authn.client.session.refresh(
                        refresh_token="ptr_xpkhwpnz2cmegsws737xbsqnmnuwtbm5",
                        user_token="ptu_wuk7tvtpswyjtlsx52b7yyi2l7zotv4a",
                    )
                """
                input = m.ClientSessionRefreshRequest(refresh_token=refresh_token, user_token=user_token)
                return await self.request.post(
                    "v2/client/session/refresh", m.ClientSessionRefreshResult, data=input.model_dump(exclude_none=True)
                )

        class PasswordAsync(ServiceBaseAsync):
            service_name = SERVICE_NAME

            def __init__(
                self,
                token: str,
                config: PangeaConfig | None = None,
                logger_name: str = "pangea",
            ) -> None:
                super().__init__(token, config, logger_name=logger_name)

            async def change(
                self, token: str, old_password: str, new_password: str
            ) -> PangeaResponse[m.ClientPasswordChangeResult]:
                """
                Change a user's password

                Change a user's password given the current password.

                OperationId: authn_post_v2_client_password_change

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
                    "v2/client/password/change", m.ClientPasswordChangeResult, data=input.model_dump(exclude_none=True)
                )

            async def expire(self, user_id: str) -> PangeaResponse[PangeaResponseResult]:
                """
                Expire a user's password

                Expire a user's password.

                OperationId: authn_post_v2_user_password_expire

                Args:
                    user_id: The identity of a user or a service.

                Returns:
                    A PangeaResponse with an empty object in the response.result field.

                Examples:
                    await authn.client.password.expire("pui_[...]")
                """
                return await self.request.post("v2/user/password/expire", PangeaResponseResult, {"id": user_id})

        class TokenAsync(ServiceBaseAsync):
            service_name = SERVICE_NAME

            def __init__(
                self,
                token: str,
                config: PangeaConfig | None = None,
                logger_name: str = "pangea",
            ) -> None:
                super().__init__(token, config, logger_name=logger_name)

            async def check(self, token: str) -> PangeaResponse[m.ClientTokenCheckResult]:
                """
                Check a token

                Look up a token and return its contents.

                OperationId: authn_post_v2_client_token_check

                Args:
                    token (str): A token value

                Returns:
                    A PangeaResponse with a token and its information in the response.result field.
                        Available response fields can be found in our
                        [API Documentation](https://pangea.cloud/docs/api/authn/flow#/v2/client/token/check).

                Examples:
                    response = authn.client.token_endpoints.check(
                        token="ptu_wuk7tvtpswyjtlsx52b7yyi2l7zotv4a",
                    )
                """
                input = m.ClientTokenCheckRequest(token=token)
                return await self.request.post(
                    "v2/client/token/check", m.ClientTokenCheckResult, data=input.model_dump(exclude_none=True)
                )

    class UserAsync(ServiceBaseAsync):
        service_name = SERVICE_NAME

        def __init__(
            self,
            token: str,
            config: PangeaConfig | None = None,
            logger_name: str = "pangea",
        ) -> None:
            super().__init__(token, config, logger_name=logger_name)
            self.profile = AuthNAsync.UserAsync.ProfileAsync(token, config, logger_name=logger_name)
            self.authenticators = AuthNAsync.UserAsync.AuthenticatorsAsync(token, config, logger_name=logger_name)
            self.invites = AuthNAsync.UserAsync.InvitesAsync(token, config, logger_name=logger_name)

        async def create(
            self,
            email: str,
            profile: m.Profile,
            *,
            username: str | None = None,
        ) -> PangeaResponse[m.UserCreateResult]:
            """
            Create User

            Create a user.

            OperationId: authn_post_v2_user_create

            Args:
                email: An email address.
                profile: A user profile as a collection of string properties.
                username: A username.

            Returns:
                A PangeaResponse with a user and its information in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn/user#/v2/user/create).

            Examples:
                response = authn.user.create(
                    email="joe.user@email.com",
                    profile={
                        "first_name": "Joe",
                        "last_name": "User",
                    }
                )
            """
            input = m.UserCreateRequest(
                email=email,
                profile=profile,
                username=username,
            )
            return await self.request.post(
                "v2/user/create", m.UserCreateResult, data=input.model_dump(exclude_none=True)
            )

        async def delete(
            self, email: str | None = None, id: str | None = None, *, username: str | None = None
        ) -> PangeaResponse[m.UserDeleteResult]:
            """
            Delete User

            Delete a user.

            OperationId: authn_post_v2_user_delete

            Args:
                email: An email address.
                id: The id of a user or a service.
                username: A username.

            Returns:
                A PangeaResponse with an empty object in the response.result field.

            Examples:
                authn.user.delete(email="example@example.com")
            """
            input = m.UserDeleteRequest(email=email, id=id, username=username)
            return await self.request.post(
                "v2/user/delete", m.UserDeleteResult, data=input.model_dump(exclude_none=True)
            )

        async def invite(
            self,
            inviter: str,
            email: str,
            callback: str,
            state: str,
        ) -> PangeaResponse[m.UserInviteResult]:
            """
            Invite User

            Send an invitation to a user.

            OperationId: authn_post_v2_user_invite

            Args:
                inviter (str): An email address
                email (str): An email address
                callback (str): A login callback URI
                state (str): State tracking string for login callbacks

            Returns:
                A PangeaResponse with a pending user invitation in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn/invite#/v2/user/invite).

            Examples:
                response = authn.user.invite(
                    inviter="admin@email.com",
                    email="joe.user@email.com",
                    callback="/callback",
                    state="pcb_zurr3lkcwdp5keq73htsfpcii5k4zgm7"
                )
            """
            input = m.UserInviteRequest(
                inviter=inviter,
                email=email,
                callback=callback,
                state=state,
            )
            return await self.request.post(
                "v2/user/invite", m.UserInviteResult, data=input.model_dump(exclude_none=True)
            )

        async def update(
            self,
            disabled: bool,
            id: str | None = None,
            email: str | None = None,
            *,
            username: str | None = None,
        ) -> PangeaResponse[m.UserUpdateResult]:
            """
            Update user's settings

            Update user's settings.

            OperationId: authn_post_v2_user_update

            Args:
                disabled: New disabled value.
                    Disabling a user account will prevent them from logging in.
                id: The identity of a user or a service.
                email: An email address.
                username: A username.

            Returns:
                A PangeaResponse with a user and its information in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn/user#/v2/user/update).

            Examples:
                response = authn.user.update(
                    email="joe.user@email.com",
                    disabled=True,
                )
            """
            input = m.UserUpdateRequest(
                id=id,
                email=email,
                disabled=disabled,
                username=username,
            )

            return await self.request.post(
                "v2/user/update", m.UserUpdateResult, data=input.model_dump(exclude_none=True)
            )

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

            OperationId: authn_post_v2_user_list

            Args:
                filter (dict, optional):
                last (str, optional): Reflected value from a previous response to obtain the next page of results.
                order (m.ItemOrder, optional): Order results asc(ending) or desc(ending).
                order_by (m.UserListOrderBy, optional): Which field to order results by.
                size (int, optional): Maximum results to include in the response. Minimum: 1.

            Returns:
                A PangeaResponse with a list of users in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn/user#/v2/user/list).

            Examples:
                response = authn.user.list()
            """
            if isinstance(filter, dict):
                filter = m.UserListFilter(**filter)

            input = m.UserListRequest(
                filter=filter,
                last=last,
                order=order,
                order_by=order_by,
                size=size,
            )
            return await self.request.post("v2/user/list", m.UserListResult, data=input.model_dump(exclude_none=True))

        class InvitesAsync(ServiceBaseAsync):
            service_name = SERVICE_NAME

            def __init__(
                self,
                token: str,
                config: PangeaConfig | None = None,
                logger_name: str = "pangea",
            ) -> None:
                super().__init__(token, config, logger_name=logger_name)

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

                OperationId: authn_post_v2_user_invite_list

                Args:
                    filter (dict, optional):
                    last (str, optional): Reflected value from a previous response to obtain the next page of results.
                    order (m.ItemOrder, optional): Order results asc(ending) or desc(ending).
                    order_by (m.UserInviterOrderBy, optional): Which field to order results by.
                    size (int, optional): Maximum results to include in the response. Minimum: 1.

                Returns:
                    A PangeaResponse with a list of pending user invitations in the response.result field.
                        Available response fields can be found in our
                        [API Documentation](https://pangea.cloud/docs/api/authn/invite#/v2/user/invite/list).
                Examples:
                    response = authn.user.invites.list()
                """
                if isinstance(filter, dict):
                    filter = m.UserInviteListFilter(**filter)

                input = m.UserInviteListRequest(filter=filter, last=last, order=order, order_by=order_by, size=size)
                return await self.request.post(
                    "v2/user/invite/list", m.UserInviteListResult, data=input.model_dump(exclude_none=True)
                )

            async def delete(self, id: str) -> PangeaResponse[m.UserInviteDeleteResult]:
                """
                Delete Invite

                Delete a user invitation.

                OperationId: authn_post_v2_user_invite_delete

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
                    "v2/user/invite/delete", m.UserInviteDeleteResult, data=input.model_dump(exclude_none=True)
                )

        class AuthenticatorsAsync(ServiceBaseAsync):
            service_name = SERVICE_NAME

            def __init__(
                self,
                token: str,
                config: PangeaConfig | None = None,
                logger_name: str = "pangea",
            ) -> None:
                super().__init__(token, config, logger_name=logger_name)

            async def delete(
                self,
                authenticator_id: str,
                id: str | None = None,
                email: str | None = None,
                *,
                username: str | None = None,
            ) -> PangeaResponse[m.UserAuthenticatorsDeleteResult]:
                """
                Delete user authenticator

                Delete a user's authenticator.

                OperationId: authn_post_v2_user_authenticators_delete

                Args:
                    authenticator_id: An ID for an authenticator.
                    id: The identity of a user or a service.
                    email: An email address.
                    username: A username.

                Returns:
                    A PangeaResponse with an empty object in the response.result field.

                Examples:
                    authn.user.authenticators.delete(
                        authenticator_id="pau_wuk7tvtpswyjtlsx52b7yyi2l7zotv4a",
                        id="pui_xpkhwpnz2cmegsws737xbsqnmnuwtbm5",
                    )
                """
                input = m.UserAuthenticatorsDeleteRequest(
                    authenticator_id=authenticator_id, email=email, id=id, username=username
                )
                return await self.request.post(
                    "v2/user/authenticators/delete",
                    m.UserAuthenticatorsDeleteResult,
                    data=input.model_dump(exclude_none=True),
                )

            async def list(
                self, email: str | None = None, id: str | None = None, *, username: str | None = None
            ) -> PangeaResponse[m.UserAuthenticatorsListResult]:
                """
                Get user authenticators

                Get user's authenticators by identity or email.

                OperationId: authn_post_v2_user_authenticators_list

                Args:
                    email: An email address.
                    id: The identity of a user or a service.
                    username: A username.

                Returns:
                    A PangeaResponse with a list of authenticators in the response.result field.
                        Available response fields can be found in our
                        [API Documentation](https://pangea.cloud/docs/api/authn/user#/v2/user/authenticators/list).

                Examples:
                    response = authn.user.authenticators.list(
                        id="pui_xpkhwpnz2cmegsws737xbsqnmnuwtbm5",
                    )
                """
                input = m.UserAuthenticatorsListRequest(email=email, id=id, username=username)
                return await self.request.post(
                    "v2/user/authenticators/list",
                    m.UserAuthenticatorsListResult,
                    data=input.model_dump(exclude_none=True),
                )

        class ProfileAsync(ServiceBaseAsync):
            service_name = SERVICE_NAME

            def __init__(
                self,
                token: str,
                config: PangeaConfig | None = None,
                logger_name: str = "pangea",
            ) -> None:
                super().__init__(token, config, logger_name=logger_name)

            async def get(
                self, id: str | None = None, email: str | None = None, *, username: str | None = None
            ) -> PangeaResponse[m.UserProfileGetResult]:
                """
                Get user

                Get user's information by identity or email.

                OperationId: authn_post_v2_user_profile_get

                Args:
                    id: The identity of a user or a service.
                    email: An email address.
                    username: A username.

                Returns:
                    A PangeaResponse with a user and its information in the response.result field.
                        Available response fields can be found in our
                        [API Documentation](https://pangea.cloud/docs/api/authn/user#/v2/user/profile/get).

                Examples:
                    response = authn.user.profile.get(
                        email="joe.user@email.com",
                    )
                """
                input = m.UserProfileGetRequest(id=id, email=email, username=username)
                return await self.request.post(
                    "v2/user/profile/get", m.UserProfileGetResult, data=input.model_dump(exclude_none=True)
                )

            async def update(
                self,
                profile: m.Profile,
                id: str | None = None,
                email: str | None = None,
                *,
                username: str | None = None,
            ) -> PangeaResponse[m.UserProfileUpdateResult]:
                """
                Update user

                Update user's information by identity or email.

                OperationId: authn_post_v2_user_profile_update

                Args:
                    profile: Updates to a user profile.
                    id: The identity of a user or a service.
                    email: An email address.
                    username: A username.

                Returns:
                    A PangeaResponse with a user and its information in the response.result field.
                        Available response fields can be found in our
                        [API Documentation](https://pangea.cloud/docs/api/authn/user#/v2/user/profile/update).

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
                    username=username,
                )
                return await self.request.post(
                    "v2/user/profile/update", m.UserProfileUpdateResult, data=input.model_dump(exclude_none=True)
                )

    class FlowAsync(ServiceBaseAsync):
        service_name = SERVICE_NAME

        def __init__(
            self,
            token: str,
            config: PangeaConfig | None = None,
            logger_name: str = "pangea",
        ) -> None:
            super().__init__(token, config, logger_name=logger_name)

        async def complete(self, flow_id: str) -> PangeaResponse[m.FlowCompleteResult]:
            """
            Complete sign-up/sign-in

            Complete a login or sign-up flow.

            OperationId: authn_post_v2_flow_complete

            Args:
                flow_id (str): An ID for a login or signup flow

            Returns:
                A PangeaResponse with credentials for a login session in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn/flow#/v2/flow/complete).

            Examples:
                response = authn.flow.complete(
                    flow_id="pfl_dxiqyuq7ndc5ycjwdgmguwuodizcaqhh",
                )
            """
            input = m.FlowCompleteRequest(flow_id=flow_id)
            return await self.request.post(
                "v2/flow/complete", m.FlowCompleteResult, data=input.model_dump(exclude_none=True)
            )

        async def restart(
            self, flow_id: str, choice: m.FlowChoice, data: m.FlowRestartData = {}
        ) -> PangeaResponse[m.FlowRestartResult]:
            """
            Restart a sign-up/sign-in flow

            Restart a signup-up/in flow choice.

            OperationId: authn_post_v2_flow_restart

            Args:
                flow_id (str): An ID for a login or signup flow
                choice (m.FlowChoice): Flow choice
                data (m.FlowRestartData):

            Returns:
                A PangeaResponse with information about next steps needed
                    to complete a flow in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn/flow#/v2/flow/restart).

            Examples:
                response = authn.flow.restart(
                    flow_id="pfl_dxiqyuq7ndc5ycjwdgmguwuodizcaqhh",
                    choice=FlowChoice.PASSWORD,
                    data: {},
                )
            """

            input = m.FlowRestartRequest(flow_id=flow_id, choice=choice, data=data)
            return await self.request.post(
                "v2/flow/restart", m.FlowRestartResult, data=input.model_dump(exclude_none=True)
            )

        async def start(
            self,
            cb_uri: Optional[str] = None,
            email: Optional[str] = None,
            flow_types: Optional[List[m.FlowType]] = None,
            invitation: Optional[str] = None,
        ) -> PangeaResponse[m.FlowStartResult]:
            """
            Start a sign-up/sign-in flow

            Start a new signup or signin flow.

            OperationId: authn_post_v2_flow_start

            Args:
                cb_uri (str, optional): A login callback URI
                email (str, optional): An email address
                flow_types (List[m.FlowType], optional): A list of flow types
                invitation (str, optional): A one-time ticket

            Returns:
                A PangeaResponse with information about next steps needed
                    to complete a flow in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn/flow#/v2/flow/start).

            Examples:
                response = authn.flow.start(
                    cb_uri="https://www.myserver.com/callback",
                    email="joe.user@email.com",
                    flow_types=[
                        FlowType.SIGNUP,
                        FlowType.SIGNIN,
                    ],
                )
            """
            input = m.FlowStartRequest(cb_uri=cb_uri, email=email, flow_types=flow_types, invitation=invitation)
            return await self.request.post("v2/flow/start", m.FlowStartResult, data=input.model_dump(exclude_none=True))

        async def update(
            self, flow_id: str, choice: m.FlowChoice, data: m.FlowUpdateData = {}
        ) -> PangeaResponse[m.FlowUpdateResult]:
            """
            Update a sign-up/sign-in flow

            Update a sign-up/sign-in flow.

            OperationId: authn_post_v2_flow_update

            Args:
                flow_id (str): An ID for a login or signup flow
                choice (m.FlowChoice): Flow choice
                data (dict):

            Returns:
                A PangeaResponse with information about next steps needed
                    to complete a flow in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn/flow#/v2/flow/update).

            Examples:
                response = authn.flow.update(
                    flow_id="pfl_dxiqyuq7ndc5ycjwdgmguwuodizcaqhh",
                    choice=FlowChoice.PASSWORD,
                    data={
                        "password": "someNewPasswordHere",
                    },
                )
            """

            input = m.FlowUpdateRequest(flow_id=flow_id, choice=choice, data=data)
            return await self.request.post(
                "v2/flow/update", m.FlowUpdateResult, data=input.model_dump(exclude_none=True)
            )

    class AgreementsAsync(ServiceBaseAsync):
        service_name = SERVICE_NAME

        def __init__(
            self,
            token: str,
            config: PangeaConfig | None = None,
            logger_name: str = "pangea",
        ) -> None:
            super().__init__(token, config, logger_name=logger_name)

        async def create(
            self, type: m.AgreementType, name: str, text: str, active: Optional[bool] = None
        ) -> PangeaResponse[m.AgreementCreateResult]:
            """
            Create an agreement

            Create an agreement.

            OperationId: authn_post_v2_agreements_create

            Args:
                type (m.AgreementType): An agreement type
                name (str): A name to describe the agreement.
                text (str): The body of the agreement.
                active (bool, optional): A flag to that marks which of the agreements is currently active.

            Returns:
                A PangeaResponse with a EULA object in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn/agreements#/v2/agreements/create).

            Examples:
                response = authn.agreements.create(
                    type=AgreementType.EULA,
                    name="EULA_V1",
                    text="You agree to behave yourself while logged in.",
                )
            """

            input = m.AgreementCreateRequest(type=type, name=name, text=text, active=active)
            return await self.request.post(
                "v2/agreements/create", m.AgreementCreateResult, data=input.model_dump(exclude_none=True)
            )

        async def delete(self, type: m.AgreementType, id: str) -> PangeaResponse[m.AgreementDeleteResult]:
            """
            Delete an agreement

            Delete an agreement.

            OperationId: authn_post_v2_agreements_delete

            Args:
                type (m.AgreementType): An agreement type
                id (str): An ID for an agreement

            Returns:
                A PangeaResponse with an empty object in the response.result field.

            Examples:
                authn.agreements.delete(
                    type=AgreementType.EULA,
                    id="peu_wuk7tvtpswyjtlsx52b7yyi2l7zotv4a",
                )
            """

            input = m.AgreementDeleteRequest(type=type, id=id)
            return await self.request.post(
                "v2/agreements/delete", m.AgreementDeleteResult, data=input.model_dump(exclude_none=True)
            )

        async def list(
            self,
            filter: Optional[Union[Dict, m.AgreementListFilter]] = None,
            last: Optional[str] = None,
            order: Optional[m.ItemOrder] = None,
            order_by: Optional[m.AgreementListOrderBy] = None,
            size: Optional[int] = None,
        ) -> PangeaResponse[m.AgreementListResult]:
            """
            List agreements

            List agreements.

            OperationId: authn_post_v2_agreements_list

            Args:
                filter (dict, optional):
                last (str, optional): Reflected value from a previous response to obtain the next page of results.
                order (str, optional): Order results asc(ending) or desc(ending).
                order_by (str, optional): Which field to order results by.
                size (int, optional): Maximum results to include in the response. Minimum: 1.

            Returns:
                A PangeaResponse with a list of EULA objects in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn/agreements#/v2/agreements/list).

            Examples:
                response = authn.agreements.list()
            """
            if isinstance(filter, dict):
                filter = m.AgreementListFilter(**filter)

            input = m.AgreementListRequest(filter=filter, last=last, order=order, order_by=order_by, size=size)
            return await self.request.post(
                "v2/agreements/list", m.AgreementListResult, data=input.model_dump(exclude_none=True)
            )

        async def update(
            self,
            type: m.AgreementType,
            id: str,
            name: Optional[str] = None,
            text: Optional[str] = None,
            active: Optional[bool] = None,
        ) -> PangeaResponse[m.AgreementUpdateResult]:
            """
            Update agreement

            Update agreement.

            OperationId: authn_post_v2_agreements_update

            Args:
                type (m.AgreementType): An agreement type
                id (str): An ID for an agreement
                name (str, optional): The name of the agreement.
                text (str, optional): The body of the agreement.
                active (bool, optional): A flag to that marks which of the agreements is currently active.

            Returns:
                A PangeaResponse with the updated EULA object in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn/agreements#/v2/agreements/update).

            Examples:
                response = authn.agreements.update(
                    type=AgreementType.EULA,
                    id="peu_wuk7tvtpswyjtlsx52b7yyi2l7zotv4a",
                    text="You agree to behave yourself while logged in. Don't be evil.",
                    active=True,
                )
            """

            input = m.AgreementUpdateRequest(type=type, id=id, name=name, text=text, active=active)
            return await self.request.post(
                "v2/agreements/update", m.AgreementUpdateResult, data=input.model_dump(exclude_none=True)
            )

# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

from typing import Dict, List, Optional, Union

import pangea.services.authn.models as m
from pangea.response import PangeaResponse
from pangea.services.base import ServiceBase

SERVICE_NAME = "authn"


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
        self.agreements = AuthN.Agreements(token, config, logger_name=logger_name)

    class Session(ServiceBase):
        service_name = SERVICE_NAME

        def __init__(
            self,
            token,
            config=None,
            logger_name="pangea",
        ):
            super().__init__(token, config, logger_name=logger_name)

        def invalidate(self, session_id: str) -> PangeaResponse[m.SessionInvalidateResult]:
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
            return self.request.post(
                "v2/session/invalidate", m.SessionInvalidateResult, data=input.dict(exclude_none=True)
            )

        def list(
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
                response = authn.session.list()
            """
            input = m.SessionListRequest(filter=filter, last=last, order=order, order_by=order_by, size=size)
            return self.request.post("v2/session/list", m.SessionListResults, data=input.dict(exclude_none=True))

        def logout(self, user_id: str) -> PangeaResponse[m.SessionLogoutResult]:
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
            return self.request.post("v2/session/logout", m.SessionLogoutResult, data=input.dict(exclude_none=True))

    class Client(ServiceBase):
        service_name = SERVICE_NAME

        def __init__(
            self,
            token,
            config=None,
            logger_name="pangea",
        ):
            super().__init__(token, config, logger_name=logger_name)
            self.session = AuthN.Client.Session(token, config, logger_name=logger_name)
            self.password = AuthN.Client.Password(token, config, logger_name=logger_name)
            self.token_endpoints = AuthN.Client.Token(token, config, logger_name=logger_name)

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
            return self.request.post("v2/client/userinfo", m.ClientUserinfoResult, data=input.dict(exclude_none=True))

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
            return self.request.post("v2/client/jwks", m.ClientJWKSResult, {})

        class Session(ServiceBase):
            service_name = SERVICE_NAME

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            def invalidate(self, token: str, session_id: str) -> PangeaResponse[m.ClientSessionInvalidateResult]:
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
                return self.request.post(
                    "v2/client/session/invalidate", m.ClientSessionInvalidateResult, data=input.dict(exclude_none=True)
                )

            def list(
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
                    response = authn.client.session.list(
                        token="ptu_wuk7tvtpswyjtlsx52b7yyi2l7zotv4a",
                    )
                """
                input = m.ClientSessionListRequest(
                    token=token, filter=filter, last=last, order=order, order_by=order_by, size=size
                )
                return self.request.post(
                    "v2/client/session/list", m.ClientSessionListResults, data=input.dict(exclude_none=True)
                )

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
                return self.request.post(
                    "v2/client/session/logout", m.ClientSessionLogoutResult, data=input.dict(exclude_none=True)
                )

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
                return self.request.post(
                    "v2/client/session/refresh", m.ClientSessionRefreshResult, data=input.dict(exclude_none=True)
                )

        class Password(ServiceBase):
            service_name = SERVICE_NAME

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

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
                return self.request.post(
                    "v2/client/password/change", m.ClientPasswordChangeResult, data=input.dict(exclude_none=True)
                )

        class Token(ServiceBase):
            service_name = SERVICE_NAME

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
                    response = authn.client.token_endpoints.check(
                        token="ptu_wuk7tvtpswyjtlsx52b7yyi2l7zotv4a",
                    )
                """
                input = m.ClientTokenCheckRequest(token=token)
                return self.request.post(
                    "v2/client/token/check", m.ClientTokenCheckResult, data=input.dict(exclude_none=True)
                )

    class User(ServiceBase):
        service_name = SERVICE_NAME

        def __init__(
            self,
            token,
            config=None,
            logger_name="pangea",
        ):
            super().__init__(token, config, logger_name=logger_name)
            self.profile = AuthN.User.Profile(token, config, logger_name=logger_name)
            self.authenticators = AuthN.User.Authenticators(token, config, logger_name=logger_name)

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
            return self.request.post("v2/user/create", m.UserCreateResult, data=input.dict(exclude_none=True))

        def delete(self, email: Optional[str] = None, id: Optional[str] = None) -> PangeaResponse[m.UserDeleteResult]:
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
            return self.request.post("v2/user/delete", m.UserDeleteResult, data=input.dict(exclude_none=True))

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

            return self.request.post("v2/user/update", m.UserUpdateResult, data=input.dict(exclude_none=True))

        def list(
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
                response = authn.user.list()
            """
            input = m.UserListRequest(
                filter=filter,
                last=last,
                order=order,
                order_by=order_by,
                size=size,
            )
            return self.request.post("v2/user/list", m.UserListResult, data=input.dict(exclude_none=True))

        class Authenticators(ServiceBase):
            service_name = SERVICE_NAME

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

            def delete(
                self, user_id: str, mfa_provider: m.MFAProvider
            ) -> PangeaResponse[m.UserAuthenticatorsDeleteResult]:
                """
                TODO: Docs
                """
                input = m.UserAuthenticatorsDeleteRequest(user_id=user_id, mfa_provider=mfa_provider)
                return self.request.post(
                    "v2/user/authenticators/delete",
                    m.UserAuthenticatorsDeleteResult,
                    data=input.dict(exclude_none=True),
                )

            def list(
                self, email: Optional[str] = None, id: Optional[str] = None
            ) -> PangeaResponse[m.UserAuthenticatorsListResult]:
                """
                TODO: Docs
                """
                input = m.UserAuthenticatorsListRequest(email=email, id=id)
                return self.request.post(
                    "v2/user/authenticators/list", m.UserAuthenticatorsListResult, data=input.dict(exclude_none=True)
                )

        class Profile(ServiceBase):
            service_name = SERVICE_NAME

            def __init__(
                self,
                token,
                config=None,
                logger_name="pangea",
            ):
                super().__init__(token, config, logger_name=logger_name)

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
                return self.request.post(
                    "v2/user/profile/get", m.UserProfileGetResult, data=input.dict(exclude_none=True)
                )

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
                return self.request.post(
                    "v2/user/profile/update", m.UserProfileUpdateResult, data=input.dict(exclude_none=True)
                )

    class Flow(ServiceBase):
        service_name = SERVICE_NAME

        def __init__(
            self,
            token,
            config=None,
            logger_name="pangea",
        ):
            super().__init__(token, config, logger_name=logger_name)

        def complete(self, flow_id: str) -> PangeaResponse[m.FlowCompleteResult]:
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
                response = authn.flow.complete(
                    flow_id="pfl_dxiqyuq7ndc5ycjwdgmguwuodizcaqhh",
                )
            """
            input = m.FlowCompleteRequest(flow_id=flow_id)
            return self.request.post("v2/flow/complete", m.FlowCompleteResult, data=input.dict(exclude_none=True))

        def restart(
            self, flow_id: str, choice: m.FlowChoice, data: m.FlowRestartData = {}
        ) -> PangeaResponse[m.FlowRestartResult]:
            # TODO: docs

            input = m.FlowRestartRequest(flow_id=flow_id, choice=choice, data=data)
            return self.request.post("v2/flow/restart", m.FlowRestartResult, data=input.dict(exclude_none=True))

        def start(
            self,
            cb_uri: Optional[str] = None,
            email: Optional[str] = None,
            flow_types: Optional[List[m.FlowType]] = None,
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
                invitation (str, optional): A one-time ticket

            Returns:
                A PangeaResponse with information about next steps needed
                    to complete a flow in the response.result field.
                    Available response fields can be found in our
                    [API Documentation](https://pangea.cloud/docs/api/authn#start-a-sign-up-in).

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
            return self.request.post("v2/flow/start", m.FlowStartResult, data=input.dict(exclude_none=True))

        def update(
            self, flow_id: str, choice: m.FlowChoice, data: m.FlowUpdateData = {}
        ) -> PangeaResponse[m.FlowUpdateResult]:
            # TODO: docs

            input = m.FlowUpdateRequest(flow_id=flow_id, choice=choice, data=data)
            return self.request.post("v2/flow/update", m.FlowUpdateResult, data=input.dict(exclude_none=True))

    class Agreements(ServiceBase):
        service_name = SERVICE_NAME

        def __init__(
            self,
            token,
            config=None,
            logger_name="pangea",
        ):
            super().__init__(token, config, logger_name=logger_name)

        def create(
            self, type: m.AgreementType, name: str, text: str, active: Optional[bool] = None
        ) -> PangeaResponse[m.AgreementCreateResult]:
            input = m.AgreementCreateRequest(type=type, name=name, text=text, active=active)
            return self.request.post(
                "v2/agreements/create", m.AgreementCreateResult, data=input.dict(exclude_none=True)
            )

        def delete(self, type: m.AgreementType, id: str) -> PangeaResponse[m.AgreementDeleteResult]:
            input = m.AgreementDeleteRequest(type=type, id=id)
            return self.request.post(
                "21/agreements/delete", m.AgreementDeleteResult, data=input.dict(exclude_none=True)
            )

        def list(
            self,
            filter: Optional[Union[Dict, m.AgreementListFilter]] = None,
            last: Optional[str] = None,
            order: Optional[m.ItemOrder] = None,
            order_by: Optional[m.AgreementListOrderBy] = None,
            size: Optional[int] = None,
        ) -> PangeaResponse[m.AgreementListResult]:
            input = m.AgreementListRequest(filter=filter, last=last, order=order, order_by=order_by, size=size)
            return self.request.post("v2/agreements/list", m.AgreementListResult, data=input.dict(exclude_none=True))

        def update(
            self,
            type: m.AgreementType,
            id: str,
            name: Optional[str] = None,
            text: Optional[str] = None,
            active: Optional[bool] = None,
        ) -> PangeaResponse[m.AgreementUpdateResult]:
            input = m.AgreementUpdateRequest(type=type, id=id, name=name, text=text, active=active)
            return self.request.post(
                "v2/agreements/update", m.AgreementUpdateResult, data=input.dict(exclude_none=True)
            )

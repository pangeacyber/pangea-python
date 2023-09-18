# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import datetime
import random
import unittest

import pangea.exceptions as pexc
from pangea import PangeaConfig
from pangea.services.authn.authn import AuthN
from pangea.services.authn.models import AgreementType, IDProvider
from pangea.tools import TestEnvironment, get_test_domain, get_test_token, logger_set_pangea_config

TEST_ENVIRONMENT = TestEnvironment.LIVE

TIME = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
RANDOM_VALUE = random.randint(0, 10000000)
EMAIL_TEST = f"user.email+test{RANDOM_VALUE}@pangea.cloud"
EMAIL_DELETE = f"user.email+delete{RANDOM_VALUE}@pangea.cloud"
EMAIL_INVITE_DELETE = f"user.email+invite_del{RANDOM_VALUE}@pangea.cloud"
EMAIL_INVITE_KEEP = f"user.email+invite_keep{RANDOM_VALUE}@pangea.cloud"
PASSWORD_OLD = "My1s+Password"
PASSWORD_NEW = "My1s+Password_new"
PROFILE_OLD = {"name": "User name", "country": "Argentina"}
PROFILE_NEW = {"age": "18"}
USER_ID = None  # Will be set once user is created

# tests that should be run in order are named with <letter><number>.
# Letter to make tests groups and number to order them inside that group


class TestAuthN(unittest.TestCase):
    def setUp(self):
        self.token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        self.config = PangeaConfig(domain=domain)
        self.authn = AuthN(self.token, config=self.config, logger_name="pangea")
        logger_set_pangea_config(logger_name=self.authn.logger.name)

    def test_authn_a1_user_create_with_password(self):
        global USER_ID
        try:
            response = self.authn.user.create(
                email=EMAIL_TEST, authenticator=PASSWORD_OLD, id_provider=IDProvider.PASSWORD
            )
            self.assertEqual(response.status, "Success")
            self.assertIsNotNone(response.result.id)
            self.assertEqual({}, response.result.profile)
            USER_ID = response.result.id

            response = self.authn.user.create(
                email=EMAIL_DELETE, authenticator=PASSWORD_OLD, id_provider=IDProvider.PASSWORD, profile=PROFILE_NEW
            )
            self.assertEqual(response.status, "Success")
            self.assertEqual(response.result.profile, PROFILE_NEW)
        except pexc.PangeaAPIException as e:
            print(e)
            self.assertTrue(False)

    def test_authn_a2_user_delete(self):
        response = self.authn.user.delete(email=EMAIL_DELETE)
        self.assertEqual(response.status, "Success")
        self.assertIsNone(response.result)

    def test_authn_a3_login_n_password_change(self):
        # This could (should) fail if test_authn_a1_user_create_with_password failed
        try:
            # login
            response_login = self.authn.user.login.password(email=EMAIL_TEST, password=PASSWORD_OLD)
            self.assertEqual(response_login.status, "Success")
            self.assertIsNotNone(response_login.result)
            self.assertIsNotNone(response_login.result.active_token)
            self.assertIsNotNone(response_login.result.refresh_token)

            # verify
            response_verify = self.authn.user.verify(
                id_provider=IDProvider.PASSWORD, email=EMAIL_TEST, authenticator=PASSWORD_OLD
            )
            self.assertEqual(response_verify.status, "Success")

            # password change
            response_change = self.authn.client.password.change(
                token=response_login.result.active_token.token, old_password=PASSWORD_OLD, new_password=PASSWORD_NEW
            )
            self.assertEqual(response_change.status, "Success")
            self.assertIsNone(response_change.result)

            # password reset
            response_reset = self.authn.user.password.reset(user_id=USER_ID, new_password=PASSWORD_NEW)
            self.assertEqual(response_reset.status, "Success")

        except pexc.PangeaAPIException as e:
            print(e)
            self.assertTrue(False)

    def test_authn_a4_user_profile(self):
        # This could (should) fail if test_authn_a1_user_create_with_password failed
        try:
            # Get profile by email. Should be empty because it was created without profile parameter
            response = self.authn.user.profile.get(email=EMAIL_TEST)
            self.assertEqual(response.status, "Success")
            self.assertIsNotNone(response.result)
            self.assertEqual(USER_ID, response.result.id)
            self.assertEqual(EMAIL_TEST, response.result.email)
            self.assertEqual({}, response.result.profile)

            response = self.authn.user.profile.get(id=USER_ID)
            self.assertEqual(response.status, "Success")
            self.assertIsNotNone(response.result)
            self.assertEqual(USER_ID, response.result.id)
            self.assertEqual(EMAIL_TEST, response.result.email)
            self.assertEqual({}, response.result.profile)

            # Update profile
            response = self.authn.user.profile.update(email=EMAIL_TEST, profile=PROFILE_OLD)
            self.assertEqual(response.status, "Success")
            self.assertIsNotNone(response.result)
            self.assertEqual(USER_ID, response.result.id)
            self.assertEqual(EMAIL_TEST, response.result.email)
            self.assertEqual(PROFILE_OLD, response.result.profile)

            # Add one new field to profile
            response = self.authn.user.profile.update(id=USER_ID, profile=PROFILE_NEW)
            self.assertEqual(response.status, "Success")
            self.assertIsNotNone(response.result)
            self.assertEqual(USER_ID, response.result.id)
            self.assertEqual(EMAIL_TEST, response.result.email)
            final_profile: dict = {}
            final_profile.update(PROFILE_OLD)
            final_profile.update(PROFILE_NEW)
            self.assertEqual(final_profile, response.result.profile)
        except pexc.PangeaAPIException as e:
            print(e)
            self.assertTrue(False)

    def test_authn_a5_user_update(self):
        response = self.authn.user.update(email=EMAIL_TEST, disabled=False, require_mfa=False)
        self.assertEqual(response.status, "Success")
        self.assertIsNotNone(response.result)
        self.assertEqual(USER_ID, response.result.id)
        self.assertEqual(EMAIL_TEST, response.result.email)
        self.assertEqual(False, response.result.require_mfa)
        self.assertEqual(False, response.result.disabled)

    def test_authn_b1_user_invite(self):
        # This could (should) fail if test_authn_user_create_with_password failed
        response = self.authn.user.invite(
            inviter=EMAIL_TEST,
            email=EMAIL_INVITE_KEEP,
            callback="https://someurl.com/callbacklink",
            state="whatshoulditbe",
        )
        self.assertEqual(response.status, "Success")
        self.assertIsNotNone(response.result)

        response = self.authn.user.invite(
            inviter=EMAIL_TEST,
            email=EMAIL_INVITE_DELETE,
            callback="https://someurl.com/callbacklink",
            state="whatshoulditbe",
        )
        self.assertEqual(response.status, "Success")
        self.assertIsNotNone(response.result)

        # Delete invite
        response_delete = self.authn.user.invites.delete(response.result.id)
        self.assertEqual(response.status, "Success")
        self.assertIsNone(response_delete.result)

    def test_authn_b2_user_invite_list(self):
        response = self.authn.user.invites.list()
        self.assertEqual(response.status, "Success")
        self.assertIsNotNone(response.result)
        self.assertGreater(len(response.result.invites), 0)

    def test_authn_c1_login_n_some_validations(self):
        # This could (should) fail if test_authn_a1_user_create_with_password failed
        try:
            response_login = self.authn.user.login.password(email=EMAIL_TEST, password=PASSWORD_NEW)
            self.assertEqual(response_login.status, "Success")
            self.assertIsNotNone(response_login.result)
            self.assertIsNotNone(response_login.result.active_token)
            self.assertIsNotNone(response_login.result.refresh_token)

            tokens = response_login.result
            # check token
            response = self.authn.client.token_endpoints.check(token=tokens.active_token.token)
            self.assertEqual(response.status, "Success")

            # refresh
            response_refresh = self.authn.client.session.refresh(
                refresh_token=tokens.refresh_token.token, user_token=tokens.active_token.token
            )
            self.assertEqual(response_refresh.status, "Success")
            tokens = response_refresh.result

            # logout
            response_logout = self.authn.client.session.logout(token=tokens.active_token.token)
            self.assertEqual(response_logout.status, "Success")

        except pexc.PangeaAPIException as e:
            print(e)
            self.assertTrue(False)

    def test_authn_c2_login_n_session_invalidate(self):
        # This could (should) fail if test_authn_a1_user_create_with_password failed
        try:
            response_login = self.authn.user.login.password(email=EMAIL_TEST, password=PASSWORD_NEW)
            self.assertEqual(response_login.status, "Success")
            self.assertIsNotNone(response_login.result)
            self.assertIsNotNone(response_login.result.active_token)
            self.assertIsNotNone(response_login.result.refresh_token)

            # list sessions
            response = self.authn.session.list()
            self.assertEqual(response.status, "Success")
            self.assertIsNotNone(response.result)
            self.assertGreater(len(response.result.sessions), 0)
            for session in response.result.sessions:
                try:
                    self.authn.session.invalidate(session_id=session.id)
                except pexc.PangeaAPIException:
                    print(f"Fail to invalidate session_id: {session.id}")
                    pass

        except pexc.PangeaAPIException as e:
            print(e)
            self.assertTrue(False)

    def test_authn_c2_login_n_client_session_invalidate(self):
        # This could (should) fail if test_authn_a1_user_create_with_password failed
        try:
            response_login = self.authn.user.login.password(email=EMAIL_TEST, password=PASSWORD_NEW)
            self.assertEqual(response_login.status, "Success")
            self.assertIsNotNone(response_login.result)
            self.assertIsNotNone(response_login.result.active_token)
            self.assertIsNotNone(response_login.result.refresh_token)
            token = response_login.result.active_token.token

            # list sessions
            response = self.authn.client.session.list(token=token)
            self.assertEqual(response.status, "Success")
            self.assertIsNotNone(response.result)
            self.assertGreater(len(response.result.sessions), 0)

            for session in response.result.sessions:
                try:
                    self.authn.client.session.invalidate(token=token, session_id=session.id)
                except pexc.PangeaAPIException as e:
                    print(f"Fail to invalidate session_id[{session.id}] token[{token}]")
                    print(e)
                    pass

        except pexc.PangeaAPIException as e:
            print(e)
            self.assertTrue(False)

    def test_authn_c3_login_n_logout_sessions(self):
        # This could (should) fail if test_authn_a1_user_create_with_password failed
        try:
            response_login = self.authn.user.login.password(email=EMAIL_TEST, password=PASSWORD_NEW)
            self.assertEqual(response_login.status, "Success")
            self.assertIsNotNone(response_login.result)
            self.assertIsNotNone(response_login.result.active_token)
            self.assertIsNotNone(response_login.result.refresh_token)

            # session logout
            response_logout = self.authn.session.logout(user_id=response_login.result.active_token.id)
            self.assertEqual(response_logout.status, "Success")

        except pexc.PangeaAPIException as e:
            print(e)
            self.assertTrue(False)

    def test_authn_z1_user_list(self):
        response = self.authn.user.list()
        self.assertEqual(response.status, "Success")
        self.assertIsNotNone(response.result)
        self.assertGreater(len(response.result.users), 0)
        for user in response.result.users:
            try:
                self.authn.user.delete(email=user.email)
            except pexc.PangeaAPIException:
                print(f"Fail to delete user email: {user.email}")
                pass

    def agreements_cycle(self, type: AgreementType):
        name = f"{type}_{TIME}"
        text = "This is agreement text"
        active = False

        # Create agreement
        response = self.authn.agreements.create(type=type, name=name, text=text, active=active)
        self.assertEqual(response.result.type, str(type))
        self.assertEqual(response.result.name, name)
        self.assertEqual(response.result.text, text)
        self.assertEqual(response.result.active, active)
        id = response.result.id
        self.assertIsNotNone(id)

        # Update agreement
        new_name = f"{name}_v2"
        new_text = f"{text} v2"

        response = self.authn.agreements.update(type=type, id=id, name=new_name, text=new_text, active=active)
        self.assertEqual(response.result.name, new_name)
        self.assertEqual(response.result.text, new_text)
        self.assertEqual(response.result.active, active)

        # List
        response = self.authn.agreements.list()
        self.assertGreater(response.result.count, 0)
        self.assertGreater(len(response.result.agreements), 0)
        count = response.result.count  # save current value

        # delete
        response = self.authn.agreements.delete(type=type, id=id)

        # List again
        response = self.authn.agreements.list()
        self.assertEqual(response.result.count, count - 1)

    def test_agreements_eula(self):
        self.agreements_cycle(AgreementType.EULA)

    def test_agreements_privacy_policy(self):
        self.agreements_cycle(AgreementType.PRIVACY_POLICY)

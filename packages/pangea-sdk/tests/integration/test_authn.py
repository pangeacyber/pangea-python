# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import os
import random
import unittest

import pangea.exceptions as pexc
from pangea import PangeaConfig
from pangea.response import PangeaResponse, ResponseStatus
from pangea.services.authn.authn import AuthN
from pangea.services.authn.models import IDProvider

RANDOM_VALUE = random.randint(0, 10000000)
EMAIL_TEST = f"andres.tournour+test{RANDOM_VALUE}@pangea.cloud"
EMAIL_DELETE = f"andres.tournour+delete{RANDOM_VALUE}@pangea.cloud"
EMAIL_INVITE = f"andres.tournour+invite{RANDOM_VALUE}@pangea.cloud"
PASSWORD_OLD = "My1s+Password"
PASSWORD_NEW = "My1s+Password_new"
PROFILE_OLD = {"name": "User name", "country": "Argentina"}
PROFILE_NEW = {"age": "18"}
USER_IDENTITY = None  # Will be set once user is created

# tests that should be run in order are named with <letter><number>. Letter to make tests groups and number to order them inside that group


def print_api_error(e: pexc.PangeaAPIException):
    print(e)
    for ef in e.errors:
        print(ef)


class TestAuthN(unittest.TestCase):
    def setUp(self):
        self.token = os.getenv("PANGEA_INTEGRATION_TOKEN")
        domain = os.getenv("PANGEA_INTEGRATION_DOMAIN")
        self.config = PangeaConfig(domain=domain)
        self.authn = AuthN(self.token, config=self.config)

    def test_authn_a1_user_create_with_password(self):
        global USER_IDENTITY
        response = self.authn.user_create(email=EMAIL_TEST, authenticator=PASSWORD_OLD, id_provider=IDProvider.PASSWORD)
        self.assertEqual(response.status, "Success")
        self.assertIsNotNone(response.result.identity)
        self.assertEqual({}, response.result.profile)
        USER_IDENTITY = response.result.identity

        try:
            response = self.authn.user_create(
                email=EMAIL_DELETE, authenticator=PASSWORD_OLD, id_provider=IDProvider.PASSWORD, profile=PROFILE_NEW
            )
            self.assertEqual(response.status, "Success")
            self.assertEqual(response.result.profile, PROFILE_NEW)
        except pexc.PangeaAPIException as e:
            print_api_error(e)
            self.assertTrue(False)

    def test_authn_a2_user_delete(self):
        response = self.authn.user_delete(email=EMAIL_DELETE)
        self.assertEqual(response.status, "Success")
        self.assertIsNone(response.result)

    def test_authn_a3_password_update(self):
        # This could (should) fail if test_authn_a1_user_create_with_password failed
        response = self.authn.password_update(email=EMAIL_TEST, old_secret=PASSWORD_OLD, new_secret=PASSWORD_NEW)
        self.assertEqual(response.status, "Success")
        self.assertIsNone(response.result)

    def test_authn_a4_user_login(self):
        # This could (should) fail if test_authn_a1_user_create_with_password failed
        try:
            response = self.authn.user_login(email=EMAIL_TEST, secret=PASSWORD_NEW)
            self.assertEqual(response.status, "Success")
            self.assertIsNotNone(response.result)
            self.assertEqual(USER_IDENTITY, response.result.identity)
        except pexc.PangeaAPIException as e:
            print_api_error(e)
            self.assertTrue(False)

    def test_authn_a4_user_profile(self):
        # This could (should) fail if test_authn_a1_user_create_with_password failed

        try:
            # Get profile by email. Should be empty because it was created without profile parameter
            response = self.authn.user_profile_get(email=EMAIL_TEST)
            self.assertEqual(response.status, "Success")
            self.assertIsNotNone(response.result)
            self.assertEqual(USER_IDENTITY, response.result.identity)
            self.assertEqual(EMAIL_TEST, response.result.email)
            self.assertEqual({}, response.result.profile)

            response = self.authn.user_profile_get(identity=USER_IDENTITY)
            self.assertEqual(response.status, "Success")
            self.assertIsNotNone(response.result)
            self.assertEqual(USER_IDENTITY, response.result.identity)
            self.assertEqual(EMAIL_TEST, response.result.email)
            self.assertEqual({}, response.result.profile)

            # Update profile
            response = self.authn.user_profile_update(email=EMAIL_TEST, profile=PROFILE_OLD)
            self.assertEqual(response.status, "Success")
            self.assertIsNotNone(response.result)
            self.assertEqual(USER_IDENTITY, response.result.identity)
            self.assertEqual(EMAIL_TEST, response.result.email)
            self.assertEqual(PROFILE_OLD, response.result.profile)

            # Add one new field to profile
            response = self.authn.user_profile_update(identity=USER_IDENTITY, profile=PROFILE_NEW)
            self.assertEqual(response.status, "Success")
            self.assertIsNotNone(response.result)
            self.assertEqual(USER_IDENTITY, response.result.identity)
            self.assertEqual(EMAIL_TEST, response.result.email)
            final_profile = PROFILE_OLD | PROFILE_NEW
            self.assertEqual(final_profile, response.result.profile)
        except pexc.PangeaAPIException as e:
            print_api_error(e)
            self.assertTrue(False)

    def test_authn_user_invite(self):
        # This could (should) fail if test_authn_user_create_with_password failed
        response = self.authn.user_invite(
            inviter=EMAIL_TEST, email=EMAIL_INVITE, callback="https://someurl.com/callbacklink", state="whatshoulditbe"
        )
        self.assertEqual(response.status, "Success")
        self.assertIsNotNone(response.result)

        # Delete invite
        response_delete = self.authn.user_invite_delete(response.result.id)
        self.assertEqual(response.status, "Success")
        self.assertIsNone(response_delete.result)

    def test_authn_user_list(self):
        response = self.authn.user_list(scopes=[], glob_scopes=[])
        self.assertEqual(response.status, "Success")
        self.assertIsNotNone(response.result)

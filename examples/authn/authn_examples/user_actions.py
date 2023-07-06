import os
import random

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services.authn.authn import AuthN
from pangea.services.authn.models import IDProvider

RANDOM_VALUE = random.randint(0, 10000000)
USER_EMAIL = f"user.email+test{RANDOM_VALUE}@pangea.cloud"  # Email to create user
PASSWORD_INITIAL = "My1s+Password"  # First password to be set to user created
PASSWORD_UPDATE = "My1s+Password_new"  # Password used to update user password
PROFILE_INITIAL = {"name": "User Name", "country": "Argentina"}  # Inicial user profile
PROFILE_UPDATE = {"age": "18"}  # Additional info to update user profile


def main():
    token = os.getenv("PANGEA_AUTHN_TOKEN")
    domain = os.getenv("PANGEA_DOMAIN")
    config = PangeaConfig(domain=domain)
    authn = AuthN(token, config=config, logger_name="pangea")

    try:
        print("Creating user...")
        response = authn.user.create(
            email=USER_EMAIL, authenticator=PASSWORD_INITIAL, id_provider=IDProvider.PASSWORD, profile=PROFILE_INITIAL
        )
        # Save user id for future use
        user_id = response.result.id
        print("User creation success. Result: ", response.result)

        print("\n\nUser login...")
        response = authn.user.login.password(email=USER_EMAIL, password=PASSWORD_INITIAL)
        # Save user token to change password
        user_token = response.result.active_token.token
        print("User login success. Result: ", response.result)

        print("\n\nUser password change...")
        response = authn.client.password.change(
            token=user_token, old_password=PASSWORD_INITIAL, new_password=PASSWORD_UPDATE
        )
        print("User password change success")

        print("\n\nGetting user profile by email...")
        response = authn.user.profile.get(email=USER_EMAIL)
        print("User get profile success. Result: ", response.result)
        print("Current profile: ", response.result.profile)

        print("\n\nGetting user profile by id...")
        response = authn.user.profile.get(id=user_id)
        print("User get profile by id success.")

        print("\n\nUpdate user profile by id...")
        # Add one new field to profile
        response = authn.user.profile.update(id=user_id, profile=PROFILE_UPDATE)
        print("Update success. Current profile: ", response.result.profile)

        print("\n\nUpdating user info...")
        response = authn.user.update(email=USER_EMAIL, disabled=False, require_mfa=False)
        print("Update user info success. Result: ", response.result)

        print("\n\nListing users...")
        response = authn.user.list()
        print(f"List users success. {response.result.count} users on this project")
        print(f"List users success. {len(response.result.users)} users listed")

        print("\n\nDeleting user...")
        response = authn.user.delete(email=USER_EMAIL)
        print("Delete user success")

    except pe.PangeaAPIException as e:
        print(f"AuthN Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

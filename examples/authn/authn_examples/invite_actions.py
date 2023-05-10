import os
import random

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services.authn.authn import AuthN

RANDOM_VALUE = random.randint(0, 10000000)
EMAIL_INVITE_1 = f"user.email+1{RANDOM_VALUE}@pangea.cloud"  # Email to create user
EMAIL_INVITE_2 = f"user.email+2{RANDOM_VALUE}@pangea.cloud"  # Email to create user
EMAIL_INVITER = f"user.email+inviter{RANDOM_VALUE}@pangea.cloud"  # Email to create user
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
        print("Inviting first user...")
        response = authn.user.invite(
            inviter=EMAIL_INVITER,
            email=EMAIL_INVITE_1,
            callback="https://someurl.com/callbacklink",
            state="invitestate",
        )
        print("Invite success. Result: ", response.result)

        print("\n\nInviting second user...")
        response = authn.user.invite(
            inviter=EMAIL_INVITER,
            email=EMAIL_INVITE_2,
            callback="https://someurl.com/callbacklink",
            state="invitestate",
        )
        id_user2 = response.result.id
        print("Invite success. Result: ", response.result)

        print("\n\nListing invites...")
        response = authn.user.invites.list()
        print(f"List success. {len(response.result.invites)} invites")
        print("\nList result:", response.result)

        # Delete invite
        print("\nDelete invite...")
        response = authn.user.invites.delete(id_user2)
        print("Delete invite success.")

        print("\n\nListing invites...")
        response = authn.user.invites.list()
        print(f"List success. {len(response.result.invites)} invites")
        print("\nList result:", response.result)

    except pe.PangeaAPIException as e:
        print(f"AuthN Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

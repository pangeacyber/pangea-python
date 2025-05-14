from __future__ import annotations

import asyncio
import os
import random

import pangea.exceptions as pe
import pangea.services.authn.models as m
from pangea.asyncio.services import AuthNAsync
from pangea.config import PangeaConfig

RANDOM_VALUE = random.randint(0, 10000000)
USER_EMAIL = f"user.email+test{RANDOM_VALUE}@pangea.cloud"  # Email to create user
PASSWORD_INITIAL = "My1s+Password"  # First password to be set to user created
PASSWORD_UPDATE = "My1s+Password_new"  # Password used to update user password
PROFILE_INITIAL = {"first_name": "Name", "last_name": "User"}  # Initial user profile
PROFILE_UPDATE = {"first_name": "NameUpdate"}  # Additional info to update user profile
CB_URI = "https://www.usgs.gov/faqs/what-was-pangea"  # Need to setup callbacks in PUC AuthN settings


async def flow_handle_password_phase(authn, flow_id, password):
    print("Update flow with password")
    return await authn.flow.update(
        flow_id=flow_id,
        choice=m.FlowChoice.PASSWORD,
        data=m.FlowUpdateDataPassword(password=password),
    )


async def flow_handle_profile_phase(authn, flow_id):
    print("Update flow with profile")
    data = m.FlowUpdateDataProfile(profile=PROFILE_INITIAL)
    return await authn.flow.update(flow_id=flow_id, choice=m.FlowChoice.PROFILE, data=data)


async def flow_handle_agreements_phase(authn, flow_id, response):
    print("Update flow with agreements if needed")
    for flow_choice in response.result.flow_choices:
        agreed = []
        if flow_choice.choice == m.FlowChoice.AGREEMENTS.value:
            agreements = dict(**flow_choice.data["agreements"])
            for _, v in agreements.items():
                agreed.append(v["id"])

    data = m.FlowUpdateDataAgreements(agreed=agreed)
    return await authn.flow.update(flow_id=flow_id, choice=m.FlowChoice.AGREEMENTS, data=data)


def choice_is_available(response, choice):
    return any(c.choice == choice for c in response.result.flow_choices)


async def main():
    token = os.getenv("PANGEA_AUTHN_TOKEN")
    domain = os.getenv("PANGEA_DOMAIN")
    config = PangeaConfig(domain=domain)
    authn = AuthNAsync(token, config=config, logger_name="pangea")

    try:
        print("Creating user...")
        print("Start flow with signup and signin")
        response = await authn.flow.start(
            email=USER_EMAIL, flow_types=[m.FlowType.SIGNUP, m.FlowType.SIGNIN], cb_uri=CB_URI
        )
        flow_id = response.result.flow_id

        while response.result.flow_phase != "phase_completed":
            if choice_is_available(response, m.FlowChoice.PASSWORD.value):
                response = await flow_handle_password_phase(authn, flow_id=flow_id, password=PASSWORD_INITIAL)
            elif choice_is_available(response, m.FlowChoice.PROFILE.value):
                response = await flow_handle_profile_phase(authn, flow_id=flow_id)
            elif choice_is_available(response, m.FlowChoice.AGREEMENTS.value):
                response = await flow_handle_agreements_phase(authn, flow_id=flow_id, response=response)
            else:
                print(f"Phase {response.result.flow_choices} not handled")
                break

        print("Complete signup/signin flow")
        complete_resp = await authn.flow.complete(flow_id=flow_id)
        print("Update flow is completed")

        user_token = complete_resp.result.active_token.token
        print("User login success. Result: ", complete_resp.result)

        print("\n\nUser password change...")
        response = await authn.client.password.change(
            token=user_token, old_password=PASSWORD_INITIAL, new_password=PASSWORD_UPDATE
        )
        print("User password change success")

        print("\n\nGetting user profile by email...")
        response = await authn.user.profile.get(email=USER_EMAIL)
        print("User get profile success. Result: ", response.result)
        print("Current profile: ", response.result.profile)
        user_id = response.result.id

        print("\n\nGetting user profile by id...")
        response = await authn.user.profile.get(id=user_id)
        print("User get profile by id success.")

        print("\n\nUpdate user profile by id...")
        # Add one new field to profile
        response = await authn.user.profile.update(id=user_id, profile=PROFILE_UPDATE)
        print("Update success. Current profile: ", response.result.profile)

        print("\n\nUpdating user info...")
        response = await authn.user.update(email=USER_EMAIL, disabled=False)
        print("Update user info success. Result: ", response.result)

        print("\n\nListing users...")
        response = await authn.user.list()
        print(f"List users success. {response.result.count} users on this project")
        print(f"List users success. {len(response.result.users)} users listed")

        print("\n\nDeleting user...")
        response = await authn.user.delete(email=USER_EMAIL)
        print("Delete user success")

    except pe.PangeaAPIException as e:
        print(f"AuthN Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")

    await authn.close()


if __name__ == "__main__":
    asyncio.run(main())

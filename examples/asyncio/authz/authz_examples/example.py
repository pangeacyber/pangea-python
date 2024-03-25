import asyncio
from os import getenv
from secrets import token_hex

from pangea.asyncio.services.authz import AuthZAsync
from pangea.config import PangeaConfig
from pangea.services.authz import Resource, Subject, Tuple, TupleListFilter

# Load configuration from environment variables.
pangea_domain = getenv("PANGEA_TOKEN", "aws.us.pangea.cloud")
pangea_authz_token = getenv("PANGEA_AUTHZ_TOKEN", "")

# Create an AuthZ API client.
authz = AuthZAsync(token=pangea_authz_token, config=PangeaConfig(domain=pangea_domain))

# Mock data.
folder_id = f"folder_{token_hex(8)}"
user_id = f"user_{token_hex(8)}"


async def main():
    # Create a tuple.
    await authz.tuple_create(
        [
            Tuple(
                resource=Resource(namespace="folder", id=folder_id),
                relation="reader",
                subject=Subject(namespace="user", id=user_id),
            )
        ]
    )
    print(f"user '{user_id}' is a 'reader' for folder '{folder_id}'")

    # Find the tuple that was just created.
    list_response = await authz.tuple_list(filter=TupleListFilter(resource_namespace="folder", resource_id=folder_id))
    # list_response.result
    # ⇒ tuples = [
    # ⇒     Tuple(
    # ⇒         resource=Resource(namespace="folder", id="folder_82fe59c0fcde13e9"),
    # ⇒         relation="reader",
    # ⇒         subject=Subject(namespace="user", id="user_ce0c2fb57043e65f", action=None),
    # ⇒     )
    # ⇒ ]

    # Check if the user is an editor of the folder.
    check_response = await authz.check(
        resource=Resource(namespace="folder", id=folder_id),
        action="editor",
        subject=Subject(namespace="user", id=user_id),
    )
    # check_response.result
    # ⇒ allowed=False

    # They're not an editor, but they are a reader.
    check_response = await authz.check(
        resource=Resource(namespace="folder", id=folder_id),
        action="reader",
        subject=Subject(namespace="user", id=user_id),
    )
    # check_response.result
    # ⇒ allowed=True

    # Delete the tuple.
    await authz.tuple_delete(
        [
            Tuple(
                resource=Resource(namespace="folder", id=folder_id),
                relation="reader",
                subject=Subject(namespace="user", id=user_id),
            )
        ]
    )


if __name__ == "__main__":
    asyncio.run(main())

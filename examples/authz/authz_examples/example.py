from os import getenv
from secrets import token_hex

from pangea.config import PangeaConfig
from pangea.services import AuthZ
from pangea.services.authz import Resource, Subject, Tuple, TupleListFilter

# Load configuration from environment variables.
url_template = getenv("PANGEA_URL_TEMPLATE")
assert url_template
pangea_authz_token = getenv("PANGEA_AUTHZ_TOKEN", "")

# Create an AuthZ API client.
authz = AuthZ(token=pangea_authz_token, config=PangeaConfig(base_url_template=url_template))

# Mock data.
folder_id = f"folder_{token_hex(8)}"
user_id = f"user_{token_hex(8)}"

# Create a tuple.
authz.tuple_create(
    [
        Tuple(
            resource=Resource(type="folder", id=folder_id),
            relation="reader",
            subject=Subject(type="user", id=user_id),
        )
    ]
)
print(f"user '{user_id}' is a 'reader' for folder '{folder_id}'")

# Find the tuple that was just created.
list_response = authz.tuple_list(filter=TupleListFilter(resource_type="folder", resource_id=folder_id))
# list_response.result
# ⇒ tuples = [
# ⇒     Tuple(
# ⇒         resource=Resource(type="folder", id="folder_82fe59c0fcde13e9"),
# ⇒         relation="reader",
# ⇒         subject=Subject(type="user", id="user_ce0c2fb57043e65f", action=None),
# ⇒     )
# ⇒ ]

# Check if the user is an editor of the folder.
check_response = authz.check(
    resource=Resource(type="folder", id=folder_id),
    action="editor",
    subject=Subject(type="user", id=user_id),
)
# check_response.result
# ⇒ allowed=False

# They're not an editor, but they are a reader.
check_response = authz.check(
    resource=Resource(type="folder", id=folder_id),
    action="reader",
    subject=Subject(type="user", id=user_id),
)
# check_response.result
# ⇒ allowed=True

# Delete the tuple.
authz.tuple_delete(
    [
        Tuple(
            resource=Resource(type="folder", id=folder_id),
            relation="reader",
            subject=Subject(type="user", id=user_id),
        )
    ]
)

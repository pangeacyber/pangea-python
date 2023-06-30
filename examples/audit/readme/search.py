# This is a search example to be used on repo readme file
import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import Audit

# Read your project domain from an env variable
domain = os.getenv("PANGEA_DOMAIN")

# Read your access token from an env variable
token = os.getenv("PANGEA_AUDIT_TOKEN")

# Create a Config object contain the Audit Config
config = PangeaConfig(domain=domain)

# Initialize an Audit instance using the config object
audit = Audit(token, config=config)

print("Searching...")
try:
    # Search for 'message' containing 'prevented'
    # filtered on 'source=test', with 5 results per-page
    response = audit.search(query="message:prevented", limit=5)
except pe.PangeaAPIException as e:
    # Catch exception in case something fails and print error
    print(f"Request Error: {e.response.summary}")
    for err in e.errors:
        print(f"\t{err.detail} \n")
    exit()

print("Search Request ID:", response.request_id, "\n")

print(
    f"Found {response.result.count} event(s)",
)
for row in response.result.events:
    print(
        f"{row.envelope.received_at}\t| actor: {row.envelope.event['actor']}\t| action: {row.envelope.event['action']}\t| target: {row.envelope.event['target']}\t| status: {row.envelope.event['status']}\t| message: {row.envelope.event['message']}"
    )

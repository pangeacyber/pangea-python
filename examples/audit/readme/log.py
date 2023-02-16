# This is a log example to be used on repo readme file
import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import Audit

# Read your access token from an env variable
token = os.getenv("PANGEA_AUDIT_TOKEN")

# Read your project domain from an env variable
domain = os.getenv("PANGEA_DOMAIN")

# Create a Config object contain the Audit Config
config = PangeaConfig(domain=domain)

# Initialize an Audit instance using the config object
audit = Audit(token, config=config)

print(f"Logging...")
try:
    # Create test data
    # All input fields are listed, only `message` is required
    log_response = audit.log(
        message="despicable act prevented",
        action="reboot",
        actor="villan",
        target="world",
        status="error",
        source="some device",
        verbose=True,
    )
    print(f"Response: {log_response.result}")
except pe.PangeaAPIException as e:
    # Catch exception in case something fails and print error
    print(f"Request Error: {e.response.summary}")
    for err in e.errors:
        print(f"\t{err.detail} \n")

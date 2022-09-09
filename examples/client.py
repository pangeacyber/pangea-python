import os

from pangea.client import PangeaClient
from pangea.config import PangeaConfig

# FIXME: Should we remove PangeaClient? and so this example file also. Now every services has its own config id. Or if we want to keep it we'll need a huge config struct for each service

token = os.getenv("PANGEA_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config_id = os.getenv("AUDIT_CONFIG_ID")
config = PangeaConfig(domain=domain, config_id=config_id)
client = PangeaClient(token=token, config=config)

# Search the audit log
search_term = "reboot"
search_resp = client.audit.search(search_term)

print(f'Audit Search for "{search_term}"')
for row in search_resp.result.events:
    print(f"{row.id}\t{row.created}\t{row.actor}\t{row.action}\t{row.target}\t{row.status}")
print("\n\n")

# Geolocate an IP Address
ip_address = "69.59.181.230"
print(f"Geolocate IP: {ip_address}")
ip_resp = client.locate.geolocate(ip_address)
print(f"Geolocate Status: {ip_resp.result.status} ({ip_resp.result.code})")
print("Geolocate Result:", ip_resp.result)
print("\n\n")

# Change to invalid token
print("Set an invalid token for Geolocate")
client.locate.token = "BADTOKEN"

print(f"Geolocate IP: {ip_address}")
ip_resp = client.locate.geolocate(ip_address)

print(f"Geolocate Status: {ip_resp.status} ({ip_resp.code})")
print("Geolocate Result:", ip_resp.result)
print("\n\n")

# Sanitize a string
dirty_string = "This is a secret"
print(f'Sanitize a string: "{dirty_string}"')
san_resp = client.sanitize.sanitize(ip_address)

print(f'Sanitize Result: "{san_resp.result}"')
print("\n\n")

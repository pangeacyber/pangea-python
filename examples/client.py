from pangea.client import Client

client = Client(token="USERTOKEN")

# Search the audit log
search_term = "glenn"
search_resp = client.audit.search(search_term)

print(f'Audit Search for "{search_term}"')
for row in search_resp.result.audits:
    print(
        f"{row.id}\t{row.created}\t{row.actor}\t{row.action}\t{row.target}\t{row.status}"
    )
print("\n\n")

# Geolocate an IP Address
ip_address = "69.59.181.230"
print(f"Geolocate IP: {ip_address}")
ip_resp = client.locate.geolocate(ip_address)
print(f"Geolocate Status: {ip_resp.status} ({ip_resp.code})")
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

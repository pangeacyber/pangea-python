import pangea
from pangea.services import Audit

# set base_domain with a custom port
pangea.base_domain = "localhost:8000"

# set to use http
pangea.insecure = True

# use only the base_domain, don't prepend the service name
pangea.environment = "local"

audit = Audit(token="USERTOKEN")

log_res = audit.log("reboot", "glenn", "world", "success")

print("LOG RESULT", log_res.result)

search_res = audit.search("reboot")
result = search_res.result

print("Search Request ID", search_res.request_id)

for row in search_res.result.audits:
    print(
        f"{row.id}\t{row.created}\t{row.actor}\t{row.action}\t{row.target}\t{row.status}"
    )

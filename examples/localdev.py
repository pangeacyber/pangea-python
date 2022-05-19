import os
from pangea.config import PangeaConfig
from pangea.services import Audit

"""
Configuration for development using a local audit service
"""
config = PangeaConfig(base_domain="localhost:8000", insecure=True, environment="local")
token = os.getenv("PANGEA_TOKEN")
audit = Audit(token=token, config=config)

data = {
    "action": "reboot",
    "actor": "villan",
    "target": "world",
    "status": "success",
}

log_res = audit.log(data)

print("LOG RESULT", log_res.result)

search_res = audit.search("reboot")

if search_res.success:
    print("Search Request ID", search_res.request_id)

    for row in search_res.result.audits:
        print(
            f"{row.id}\t{row.created}\t{row.actor}\t{row.action}\t{row.target}\t{row.status}"
        )
else:
    print("Search Failed:", search_res.code, search_res.status)

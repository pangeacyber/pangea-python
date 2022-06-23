import os
from pangea.config import PangeaConfig
from pangea.services import Audit

token = os.getenv("PANGEA_TOKEN")
config_id = os.getenv("AUDIT_CONFIG_ID")
config = PangeaConfig(base_domain="dev.pangea.cloud", config_id=config_id)
audit = Audit(token, config=config)

print("Log Data...")

data = {
    "action": "reboot",
    "actor": "villan",
    "target": "world",
    "status": "error",
    "message": "test",
    "source": "ppi_3tAdYJUiyssGgJJf7B1SbYLpsdPo",
}

log_response = audit.log(data=data)

if log_response.success:
    print(f"Log Request ID: {log_response.request_id}, Success: {log_response.status}")
else:
    print(f"Log Request Error: {log_response.response.text}")

print("Search Data...")

search_res = audit.search(
    query="reboot", sources=["ppi_3tAdYJUiyssGgJJf7B1SbYLpsdPo"], page_size=10
)

if search_res.success:
    print("Search Request ID:", search_res.request_id, "\n")

    print(
        f"Results: {search_res.count} of {search_res.total}",
    )
    for row in search_res.result["events"]:
        event = row["event"]

        print(
            f'{event["created_at"]}\t{event["source"]}\t{event["actor"]}\t{event["action"]}\t{event["target"]}\t{event["status"]}'
        )

else:
    print("Search Failed:", search_res.code, search_res.status, search_res.result)

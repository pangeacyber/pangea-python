import os

from pangea.config import PangeaConfig
from pangea.services import Audit

token = os.getenv("PANGEA_TOKEN")
config = PangeaConfig(base_domain="dev.pangea.cloud", insecure=False)
audit = Audit(token=token, config=config)

print("Log Data...")

data = {
		"action": "diego",
		"actor": "testing2",
		"message": "Hello",
        "status": "xxx",
		"new": "xxx",
        "old": "xxx",
        "target": "xxx"
}

log_response = audit.log(data)

print(f"Log Request ID: {log_response.request_id}, Result: {log_response.result}")

print("Search Data...")

search_res = audit.search(query="action:diego", size=5, verify_proofs = True)

if search_res.success:
    print("Search Request ID:", search_res.request_id, "\n")

    print(
        f"Results: {search_res.count} of {search_res.total} - next {search_res.next()}",
    )
    for row in search_res.result.audits:
        print(f"{row.data.message}\t{row.data.created}\t{row.data.source}\t{row.data.actor}")        

    # get the next page
    if search_res.next():
        search_res = audit.search(**search_res.next(), verify_proofs = True)
        print("Search Next", search_res.result)

else:
    print("Search Failed:", search_res.code, search_res.status)

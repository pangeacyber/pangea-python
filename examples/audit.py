from pangea.services import Audit

audit = Audit(token="USERTOKEN")

print("Log Data...")

data = {
    "action": "reboot",
    "actor": "glenn",
    "target": "world",
    "status": "success",
}

log_res = audit.log(data)

print(f"LOG Request ID: {log_res.request_id}, Result: {log_res.result}")

print("Search Data...")

search_res = audit.search("reboot")

print("Search Request ID", search_res.request_id)

for row in search_res.result.audits:
    print(
        f"{row.id}\t{row.created}\t{row.actor}\t{row.action}\t{row.target}\t{row.status}"
    )

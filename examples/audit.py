from pangea.services import Audit

audit = Audit(token="USERTOKEN")

log_res = audit.log("reboot", "glenn", "world", "success")

print("Logging Data...")
print(f"LOG Request ID: {log_res.request_id}, Result: {log_res.result}")
print("\n")
search_res = audit.search("reboot")

print("Search Request ID", search_res.request_id)

for row in search_res.result.audits:
    print(
        f"{row.id}\t{row.created}\t{row.actor}\t{row.action}\t{row.target}\t{row.status}"
    )

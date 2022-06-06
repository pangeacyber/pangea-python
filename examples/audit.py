import os
from pangea.config import PangeaConfig
from pangea.services import Audit

token = os.getenv("PANGEA_TOKEN")
config = PangeaConfig(base_domain="dev.pangea.cloud", insecure=False)
audit = Audit(token=token, config=config)

print("Log Data...")

data = {
    'actor': 'testing1',
    'message': 'zzz', 
    'created': '2022-05-30T21:07:50.687349+00:00', 
    'proof': 'W3sic2lkZSI6ICJsZWZ0IiwgImhhc2giOiAiYmIyYzFiMmJjMTNjZjJiZmU5NGJlNmNiYWU4MzIxMTJjNjMwYmNiM2M2ZWRkZDRmMDU5MDVmMjUyNTY5NDM1MSJ9LCB7InNpZGUiOiAibGVmdCIsICJoYXNoIjogImY1OThjZWY4OGY2M2JhMWQ2NTFmYzI1MzllNDM5NGQyYTc4NDQ1OGU0ZDYyY2E4MTJlMjIyZTRkMzY1NmRhNDYifSwgeyJzaWRlIjogImxlZnQiLCAiaGFzaCI6ICIxMjY1YzA4YThmOWUzYzYxZDA3ZGMxODhiMjBhYmJmMzFhMDkwMzk2N2M3YTU3MWE3MzhmMGJkMGU2OTI1YTNhIn0sIHsic2lkZSI6ICJsZWZ0IiwgImhhc2giOiAiNzg3NzY2YzdlNDIzODMyMTBhNGVlMzMwNDdkMDRhMjJlZDJkN2Y0OTEwMzZkYjQ5NjIyNDM0Y2NmODY2MjM0ZCJ9LCB7InNpZGUiOiAibGVmdCIsICJoYXNoIjogImZmNzdhNDVkMWNjOGQ5MDUwNzg1MjA5YTY1Mzc3ZmMzZTk0ZDBkMjgyOGRkYzhjMWEwNTQ3NjRhNmI2ZjFlNmUifV0=', 
    'hash': '891e5efa1040b435dd0701a18bb1b22f08d74721ae43d83c03475d104dc261be'
}

log_response = audit.log(data)

print(f"Log Request ID: {log_response.request_id}, Result: {log_response.result}")

print("Search Data...")

search_res = audit.search(query="reboot", size=5, start='2022-05-05', verify = False)

if search_res.success:
    print("Search Request ID:", search_res.request_id, "\n")

    print(
        f"Results: {search_res.count} of {search_res.total} - next {search_res.next()}",
    )
    for row in search_res.result.audits:
#        print(f"{row.created}\t{row.actor}\t{row.action}\t{row.target}\t{row.status}")
#        print(f"{row.created}\t{row.actor}\t{row.message}\t{row.proof}\t{row.hash}")
        print(f"{row.created}")

    # get the next page
    if search_res.next():
        search_res = audit.search(**search_res.next())
        print("Search Next", search_res.result)

else:
    print("Search Failed:", search_res.code, search_res.status)

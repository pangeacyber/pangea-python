# Pangea python-sdk

## Usage

### Secure Audit Service - Log Data

```
import os
from pangea.services import Audit

token = os.getenv("PANGEA_TOKEN")
audit = Audit(token=token)

data = {
    "action": "reboot",
    "actor": "villan",
    "target": "world",
    "status": "success",
}

response = audit.log(data)

print(response.result)
```

### Secure Audit Service - Search Data

```
import os
from pangea.services import Audit

token = os.getenv("PANGEA_TOKEN")
audit = Audit(token=token)

response = audit.search("reboot", size=10)

if response.success:
    print("Search Request ID:", response.request_id, "\n")

    print(
        f"Results: {response.count} of {response.total}",
    )
    for row in response.result.audits:
        print(f"{row.created}\t{row.actor}\t{row.action}\t{row.target}\t{row.status}")

else:
    print("Search Failed:", response.code, response.status)
```

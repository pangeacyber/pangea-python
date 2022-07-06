# Pangea python-sdk

## Usage

### Secure Audit Service - Log Data

```
import os
from pangea.services import Audit

# Read your access token from an env variable
token = os.getenv("PANGEA_TOKEN")

# Read the Audit Config ID from an env variable,
# required for tokens enabled for all services
config_id = os.getenv("AUDIT_CONFIG_ID")

# Create a Config object contain the Audit Config ID
config = PangeaConfig(config_id=config_id)

# Initialize an Audit instance using the config object
audit = Audit(token, config=config)

# Create test data
# All input fields are listed, only `message` is required
event = {
    "action": "reboot",
    "actor": "villan",
    "target": "world",
    "status": "error",
    "source": "test",
    "old" : "on",
    "new" : "restart",
    "message": "despicable act prevented",    
}

response = audit.log(event=data)

print(response.result)
```

### Secure Audit Service - Search Data

```
import os
from pangea.services import Audit

# Read your access token from an env variable
token = os.getenv("PANGEA_TOKEN")

# Read the Audit Config ID from an env variable
config_id = os.getenv("AUDIT_CONFIG_ID")

# Create a Config object contain the Audit Config ID
config = PangeaConfig(config_id=config_id)

# Initialize an Audit instance using the config object
audit = Audit(token, config=config)

# Search for 'message' containing 'reboot'
# filtered on 'source=test', with 5 results per-page
search_res = audit.search(
        query="message:reboot",
        sources=["test"],
        page_size=5,
        verify=False,
    )

if response.success:
    print("Search Request ID:", response.request_id, "\n")

    print(
        f"Results: {response.count} of {response.total}",
    )
    for row in response.result.events:
        print(f"{row.created}\t{row.actor}\t{row.action}\t{row.target}\t{row.status}")

else:
    print("Search Failed:", response.code, response.status)
```


## Contributing

Currently, the setup scripts only have support for Mac/ZSH environments.
Future support is incoming.

To install our linters, simply run `./dev/setup_repo.sh`
These linters will run on every `git commit` operation.

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

## Generate SDK Documentation

### Overview

Throughout the SDK, there are Python doc strings that serve as the source of our SDK docs.

The documentation pipeline here looks like:

1. Write doc strings throughout your Python code. Please refer to existing doc strings as an example of what and how to document.
1. Make your pull request.
1. After the pull request is merged, go ahead and run the `parse_module.py` script to generate the JSON docs uses for rendering.
1. Copy the output from `parse_module.py` and overwrite the existing `python_sdk.json` file in the docs repo. File is located in `platform/docs/openapi/python_sdk.json` in the Pangea monorepo. Save this and make a merge request to update the Python SDK docs in the Pangea monorepo.

### Running the autogen sdk doc script

Make sure you have all the dependencies installed. From the root of the `python-pangea` repo run:

```shell
poetry install
```

Now run the script

```shell
poetry run python parse_module.py
```

That will output the script in the terminal. If you're on a mac, you can do

```shell
poetry run python parse_module.py | pbcopy
```

to copy the output from the script into your clipboard. At the moment, a bunch of stuff will be printed to the terminal if you pipe it to `pbcopy`, but the script still works and copies the output to your clipboard.

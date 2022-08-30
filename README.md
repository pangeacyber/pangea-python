<p>
  <br />
  <a href="https://pangea.cloud?utm_source=github&utm_medium=node-sdk" target="_blank" rel="noopener noreferrer">
    <img src="https://pangea-marketing.s3.us-west-2.amazonaws.com/pangea-color.svg" alt="Pangea Logo" height="40">
  </a>
  <br />
</p>

<p>
<br />

[![documentation](https://img.shields.io/badge/documentation-pangea-blue?style=for-the-badge&labelColor=551B76)](https://pangea.cloud/docs/sdk/python/)
[![Slack](https://img.shields.io/badge/Slack-4A154B?style=for-the-badge&logo=slack&logoColor=white)](https://pangea-builders.slack.com/ssb/redirect)

<br />
</p>

# Pangea Python SDK

A Python SDK for integrating with Pangea Services.

## Setup

```
pip3 install python-pangea
# or
poetry add python-pangea
```

## Usage

### Secure Audit Service - Log Data

```
import os
from pangea.config import PangeaConfig
from pangea.services import Audit

# Read your project domain from an env variable
domain = os.getenv("PANGEA_DOMAIN)

# Read your access token from an env variable
token = os.getenv("PANGEA_TOKEN")

# Read the Audit Config ID from an env variable,
# required for tokens enabled for all services
config_id = os.getenv("AUDIT_CONFIG_ID")

# Create a Config object contain the Audit Config ID
config = PangeaConfig(base_domain=domain, config_id=config_id)

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

response = audit.log(event)

print(response.result)
```

### Secure Audit Service - Search Data

```
import os
from pangea.config import PangeaConfig
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
response = audit.search(
        query="message:prevented",
        limit=5
    )

if response.success:
    print("Search Request ID:", response.request_id, "\n")

    print(
        f"Found {response.result.count} event(s)",
    )
    for row in response.result.events:
        print(f"{row.event.received_at}\taction: {row.event.actor}\taction: {row.event.action}\ttarget: {row.event.target}\tstatus: {row.event.status}\tmessage: {row.event.message}")

else:
    print("Search Failed:", response.code, response.status)
```

### Secure Audit Service - Integrity Tools

#### Verify audit data

You can provide a single event (obtained from the PUC) or the result from a search call.
In the latter case, all the events are verified.

Vefify an existing audit log file, reads from stdin if no filename is provided.

```
python -m verify_audit [-f <filename>]
```

#### Bulk Download Audit Data

Download all audit logs for a given time range.
Datetimes must be in ISO 8601 format.
Intended for use with the deep_verify tool

```
python -m dump_audit <datetime_from> <datetime_to>
```

#### Perform Exhaustive Verification of Audit Data

Verify Audit data. This script does additional checking for any deleted entries.
Use the dump_audit tool to download the events and root to be verified.

```
python -m deep_verify -e <events file> -r <root file>
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

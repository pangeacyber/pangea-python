<a href="https://pangea.cloud?utm_source=github&utm_medium=python-sdk" target="_blank" rel="noopener noreferrer">
  <img src="https://pangea-marketing.s3.us-west-2.amazonaws.com/pangea-color.svg" alt="Pangea Logo" height="40" />
</a>

<br />

[![documentation](https://img.shields.io/badge/documentation-pangea-blue?style=for-the-badge&labelColor=551B76)][Documentation]
[![Discourse](https://img.shields.io/badge/Discourse-4A154B?style=for-the-badge&logo=discourse&logoColor=white)][Discourse]

# Pangea Python SDK

A Python SDK for integrating with Pangea services. Supports Python v3.9 and
above.

## Installation

#### GA releases

Via pip:

```bash
$ pip3 install pangea-sdk
```

Via poetry:

```bash
$ poetry add pangea-sdk
```

<a name="beta-releases"></a>

#### Beta releases

Pre-release versions may be available with the `b` (beta) denotation in the
version number. These releases serve to preview Beta and Early Access services
and APIs. Per Semantic Versioning, they are considered unstable and do not carry
the same compatibility guarantees as stable releases.
[Beta changelog](https://github.com/pangeacyber/pangea-python/blob/beta/CHANGELOG.md).

Via pip:

```bash
$ pip3 install pangea-sdk==5.5.0b2
```

Via poetry:

```bash
$ poetry add pangea-sdk==5.5.0b2
```

## Usage

- [Documentation][]
- [GA Examples][]
- [Beta Examples][]

General usage would be to create a token for a service through the
[Pangea Console][] and then construct an API client for that respective service.
The below example shows how this can be done for [Secure Audit Log][] to log a
simple event:

```python
import os

from pangea.config import PangeaConfig
from pangea.services import Audit

# Load client configuration from environment variables `PANGEA_AUDIT_TOKEN` and
# `PANGEA_DOMAIN`.
token = os.getenv("PANGEA_AUDIT_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)

# Create a Secure Audit Log client.
audit = Audit(token, config)

# Log a basic event.
response = audit.log(message="Hello, World!")
```

## asyncio support

asyncio support is available through the `pangea.asyncio.services` module. The
previous example may be rewritten to utilize async/await syntax like so:

```python
import asyncio
import os

from pangea.asyncio.services import AuditAsync
from pangea.config import PangeaConfig

# Load client configuration from environment variables `PANGEA_AUDIT_TOKEN` and
# `PANGEA_DOMAIN`.
token = os.getenv("PANGEA_AUDIT_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)

# Create a Secure Audit Log client.
audit = AuditAsync(token, config=config)


async def main():
    # Log a basic event.
    response = await audit.log(message="Hello, World!")

    await audit.close()


if __name__ == "__main__":
    asyncio.run(main())
```

## Secure Audit Log - Integrity Tools

The Python Pangea SDK also includes some extra features to validate Audit Service log's integrity. Here we explain how to run them.

### Verify audit data

Verify that an event or a list of events has not been tampered with. Usage:

```
usage: python -m pangea.verify_audit [-h] [--file PATH]
or
usage: poetry run python -m pangea.verify_audit [-h] [--file PATH]

Pangea Audit Verifier

options:
  -h, --help            show this help message and exit
  --file PATH, -f PATH  Input file (default: standard input).
```

It accepts multiple file formats:
- a Verification Artifact from the Pangea User Console
- a search response from the REST API:

```bash
$ curl -H "Authorization: Bearer ${PANGEA_TOKEN}" -X POST -H 'Content-Type: application/json'  --data '{"verbose": true}' https://audit.aws.us.pangea.cloud/v1/search
```


### Bulk Download Audit Data

Download all audit logs for a given time range. Start and end date should be provided,
a variety of formats is supported, including ISO-8601. The result is stored in a
json file (one json per line).

```
usage: python -m pangea.dump_audit [-h] [--token TOKEN] [--domain DOMAIN] [--output OUTPUT] start end
or
usage: poetry run python -m pangea.dump_audit [-h] [--token TOKEN] [--domain DOMAIN] [--output OUTPUT] start end

Pangea Audit Dump Tool

positional arguments:
  start                 Start timestamp. Supports a variety of formats, including ISO-8601. e.g.: 2023-06-05T18:05:15.030667Z
  end                   End timestamp. Supports a variety of formats, including ISO-8601. e.g.: 2023-06-05T18:05:15.030667Z

options:
  -h, --help            show this help message and exit
  --token TOKEN, -t TOKEN
                        Pangea token (default: env PANGEA_TOKEN)
  --domain DOMAIN, -d DOMAIN
                        Pangea base domain (default: env PANGEA_DOMAIN)
  --output OUTPUT, -o OUTPUT
                        Output file name. Default: dump-<timestamp>
```

### Perform Exhaustive Verification of Audit Data

This script performs extensive verification on a range of events of the log stream. Apart from verifying the hash
and the membership proof, it checks that there are no omissions in the stream, i.e. all the events are present and properly located.

```
usage: python -m pangea.deep_verify [-h] [--token TOKEN] [--domain DOMAIN] --file FILE
or
usage: poetry run python -m pangea.deep_verify [-h] [--token TOKEN] [--domain DOMAIN] --file FILE

Pangea Audit Event Deep Verifier

options:
  -h, --help            show this help message and exit
  --token TOKEN, -t TOKEN
                        Pangea token (default: env PANGEA_TOKEN)
  --domain DOMAIN, -d DOMAIN
                        Pangea base domain (default: env PANGEA_DOMAIN)
  --file FILE, -f FILE  Event input file. Must be a collection of JSON Objects separated by newlines
```

It accepts multiple file formats:
- a Verification Artifact from the Pangea User Console
- a file generated by the `dump_audit` command
- a search response from the REST API (see `verify_audit`)



   [Documentation]: https://pangea.cloud/docs/sdk/python/
   [GA Examples]: https://github.com/pangeacyber/pangea-python/tree/main/examples
   [Beta Examples]: https://github.com/pangeacyber/pangea-python/tree/beta/examples
   [Pangea Console]: https://console.pangea.cloud/
   [Discourse]: https://l.pangea.cloud/Jd4wlGs
   [Secure Audit Log]: https://pangea.cloud/docs/audit

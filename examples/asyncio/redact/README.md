# Pangea Python SDK examples

This is a quick example of how to set up and use the Pangea Python SDK.

## Set up

In the example root directory (`./examples/asyncio/redact`), run the following command:

```
poetry install
```

Set up the environment variables ([Instructions](https://pangea.cloud/docs/redact#set-your-environment-variables)) `PANGEA_REDACT_TOKEN` and `PANGEA_DOMAIN` with your project token configured on the Pangea User Console (token should have access to Redact service [Instructions](https://pangea.cloud/docs/admin-guide/tokens)) and with your Pangea domain.

You'll need to set up and enable some rulesets in the Redact service config.

## Run

To run examples:
```
poetry run python redact_examples/text.py
```

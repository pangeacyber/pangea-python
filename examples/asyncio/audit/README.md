# Pangea Python SDK examples

This is a quick example about how you use Pangea Python SDK, set up and run it.

## Set up

On this example root directory (`./examples/asyncio/audit`) run

```
poetry install
```

Set up environment variables ([Instructions](https://pangea.cloud/docs/audit/#set-your-environment-variables)) `PANGEA_AUDIT_TOKEN` and `PANGEA_URL_TEMPLATE` with your project token configured on Pangea User Console (token should have access to the Secure Audit Log service [Instructions](https://pangea.cloud/docs/admin-guide/tokens)) and with your Pangea base url template.

## Run

To run examples:
```
poetry run python audit_examples/log.py
```

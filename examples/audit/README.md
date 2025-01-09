# Pangea Python SDK examples

This is a quick example of how to set up and use the Pangea Python SDK.

## Set up

In the example root directory (`./examples/audit`), run the following command:

```
poetry install
```

Set up environment variables ([Instructions](https://pangea.cloud/docs/audit/#set-your-environment-variables)) `PANGEA_AUDIT_TOKEN` and `PANGEA_DOMAIN` with your project token configured on Pangea User Console (token should have access to the Secure Audit Log service [Instructions](https://pangea.cloud/docs/admin-guide/tokens)) and with your Pangea domain.


## Run

To run examples:
```
poetry run python audit_examples/log.py
```

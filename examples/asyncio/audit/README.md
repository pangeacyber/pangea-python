# Pangea Python SDK examples

This is a quick example about how you use Pangea Python SDK, set up and run it.

## Set up

On this example root directory (./examples/audit) run

```
poetry install
```

Set up environment variables ([Instructions](https://pangea.cloud/docs/getting-started/integrate/#set-environment-variables)) `PANGEA_AUDIT_TOKEN` and `PANGEA_DOMAIN` with your project token configured on Pangea User Console (token should have access to Audit service [Instructions](https://pangea.cloud/docs/getting-started/configure-services/#configure-a-pangea-service)) and with your pangea domain.


## Run

To run examples:
```
poetry run python audit_examples/log.py
```

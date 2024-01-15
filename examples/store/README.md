# Pangea Python SDK examples

This is a quick example of how to set up and use the Pangea Python SDK.

## Set up

In the example root directory (./examples/store), run the following command:

```
poetry install
```

Set up the environment variables ([Instructions](https://pangea.cloud/docs/getting-started/integrate/#set-environment-variables)) `PANGEA_STORE_TOKEN` and `PANGEA_DOMAIN` with your project token configured on the Pangea User Console (token should have access to Store service [Instructions](https://pangea.cloud/docs/getting-started/configure-services/#configure-a-pangea-service)) and with your Pangea domain.

You'll need to set up and enable some rulesets in Redact service config.

## Run

To run examples:
```
poetry run python store_examples/folder_create_n_delete.py
```

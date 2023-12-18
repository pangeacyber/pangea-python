# Pangea Python SDK examples

This is a quick example of how to set up and use the Pangea Python SDK.

## Set up

In the example root directory (./examples/authn), run the following command:

```
poetry install
```

Set up the environment variables ([Instructions](https://pangea.cloud/docs/getting-started/integrate/#set-environment-variables)) `PANGEA_AUTHN_TOKEN` and `PANGEA_DOMAIN` with your project token configured on the Pangea User Console (token should have access to AuthN service [Instructions](https://pangea.cloud/docs/getting-started/configure-services/#configure-a-pangea-service)) and with your Pangea domain.

## Run

To run examples:
```
poetry run python authn_examples/invite_actions.py
```

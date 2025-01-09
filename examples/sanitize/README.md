# Pangea Python SDK examples

This is a quick example of how to set up and use the Pangea Python SDK.

## Set up

In the example root directory (`./examples/sanitize`), run the following command:

```
poetry install
```

Set up the environment variables ([Instructions](https://pangea.cloud/docs/sanitize/#set-your-environment-variables)) `PANGEA_SANITIZE_TOKEN` and `PANGEA_DOMAIN` with your project token configured on the Pangea User Console (token should have access to Sanitize and Secure Share services [Instructions](https://pangea.cloud/docs/admin-guide/tokens)) and with your Pangea domain.

## Run

To run examples:

```
poetry run python sanitize_examples/sanitize_and_share.py
```

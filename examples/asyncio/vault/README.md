# Pangea Python SDK examples

This is a quick example of how to set up and use the Pangea Python SDK.

## Set up

In the example root directory (`./examples/asyncio/vault`), run the following command:

```
poetry install
```

Set up the environment variables ([Instructions](https://pangea.cloud/docs/vault/#set-your-environment-variables)) `PANGEA_VAULT_TOKEN` and `PANGEA_URL_TEMPLATE` with your project token configured on the Pangea User Console (token should have access to Vault service [Instructions](https://pangea.cloud/docs/admin-guide/tokens)) and with your Pangea base url template.


## Run

To run examples:
```
poetry run python vault_examples/encrypt.py
```

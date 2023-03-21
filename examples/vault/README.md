# Pangea Python SDK examples

This is a quick example about how you use Pangea Python SDK, set up and run it.

## Set up

On this example root directory (./examples/vault) run

```
poetry install
```

Set up environment variables `PANGEA_VAULT_TOKEN` and `PANGEA_DOMAIN` with your project token configured Pangea User Console (token should have access to Vault service) and with your pangea domain.

## Run

To run examples:
```
poetry run python vault_examples/encrypt.py
```

# Pangea Python SDK examples

This is a quick example about how you use Pangea Python SDK, set up and run it.

## Set up

On this example root directory (./examples/authn) run

```
poetry install
```

Set up environment variables `PANGEA_AUTHN_TOKEN` and `PANGEA_DOMAIN` with your project token configured Pangea User Console (token should have access to AuthN service) and with your pangea domain.

## Run

To run examples:
```
poetry run python authn_examples/encrypt.py
```

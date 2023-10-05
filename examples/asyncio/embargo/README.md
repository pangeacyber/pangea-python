# Pangea Python SDK examples

This is a quick example about how you use Pangea Python SDK, set up and run it.

## Set up

On this example root directory (./examples/embargo) run

```
poetry install
```

Set up environment variables ([Instructions](https://pangea.cloud/docs/getting-started/integrate/#set-environment-variables)) `PANGEA_EMBARGO_TOKEN` and `PANGEA_DOMAIN` with your project token configured on Pangea User Console (token should have access to Embargo service [Instructions](https://pangea.cloud/docs/getting-started/configure-services/#configure-a-pangea-service)) and with your pangea domain.

## Run

To run examples:
```
poetry run python embargo_examples/ip_check.py
```

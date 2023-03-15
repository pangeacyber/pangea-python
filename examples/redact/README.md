# Pangea Python SDK examples

This is a quick example about how you use Pangea Python SDK, set up and run it.

## Set up

On this example root directory (./examples/redact) run

```
poetry install
```

Set up environment variables `PANGEA_REDACT_TOKEN` and `PANGEA_DOMAIN` with your project token configured on Pangea User Console (token should have access to Redact service) and with your pangea domain.
You'll need to set up and enable some rulesets in Redact service config.

## Run

To run examples:
```
poetry run python redact_examples/text.py
```

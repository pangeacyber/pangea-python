# Pangea Python SDK examples

This is a quick example of how to set up and use the Pangea Python SDK.

## Set up

In the example root directory (`./examples/asyncio/prompt_guard`), run the following command:

```
poetry install
```

Set up the environment variables `PANGEA_PROMPT_GUARD_TOKEN` and `PANGEA_DOMAIN`
with your project token configured on the Pangea User Console (token should
[have access to][tokens] the Prompt Guard service) and with your Pangea domain.

## Run

To run examples:

```
poetry run python prompt_guard_examples/guard.py
```

[tokens]: https://pangea.cloud/docs/admin-guide/tokens

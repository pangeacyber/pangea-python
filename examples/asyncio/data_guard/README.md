# Pangea Python SDK examples

This is a quick example of how to set up and use the Pangea Python SDK.

## Set up

In the example root directory (`./examples/asyncio/data_guard`), run the following command:

```
poetry install
```

[Set up the environment variables][set-environment-variables]
`PANGEA_DATA_GUARD_TOKEN` and `PANGEA_DOMAIN` with your project token configured
on the Pangea User Console (token should [have access to][configure-a-pangea-service]
the Data Guard service) and with your Pangea domain.

## Run

To run examples:

```
poetry run python data_guard_examples/guard.py
```

[configure-a-pangea-service]: https://pangea.cloud/docs/getting-started/configure-services/#configure-a-pangea-service
[set-environment-variables]: https://pangea.cloud/docs/getting-started/integrate/#set-environment-variables

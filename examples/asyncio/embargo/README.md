# Pangea Python SDK examples

This is a quick example of how to set up and use the Pangea Python SDK.

## Set up

In the example root directory (`./examples/asyncio/embargo`), run the following command:

```
poetry install
```

Set up the environment variables `PANGEA_EMBARGO_TOKEN` and `PANGEA_URL_TEMPLATE` with
your project token configured on the Pangea User Console (token should have
access to Embargo service [Instructions](https://pangea.cloud/docs/admin-guide/tokens))
and with your Pangea base url template.

## Run

To run examples:

```
poetry run python embargo_examples/ip_check.py
```

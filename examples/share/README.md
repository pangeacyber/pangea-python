# Pangea Python SDK examples

This is a quick example of how to set up and use the Pangea Python SDK.

## Set up

In the example root directory (./examples/share), run the following command:

```
poetry install
```

Set up the environment variables ([Instructions](https://pangea.cloud/docs/share/#set-your-environment-variables)) `PANGEA_SHARE_TOKEN` and `PANGEA_URL_TEMPLATE` with your project token configured on the Pangea User Console (token should have access to Share service [Instructions](https://pangea.cloud/docs/admin-guide/tokens)) and with your Pangea base url template.

## Run

To run examples:

```
poetry run python share_examples/folder_create_and_delete.py
```

# Pangea Python SDK examples

This is a quick example of how to set up and use the Pangea Python SDK.

## Set up

In the example root directory (`./examples/file_scan`), run the following command:

```
poetry install
```

Set up the environment variables ([Instructions](https://pangea.cloud/docs/file-scan/getting-started/#set-environment-variables)) `PANGEA_FILE_SCAN_TOKEN` and `PANGEA_URL_TEMPLATE` with your project token configured on the Pangea User Console (token should have access to File Scan service [Instructions](https://pangea.cloud/docs/admin-guide/tokens)) and with your Pangea base url template.

## Run

To run examples:

```
poetry run python file_scan_examples/file_scan_sync_crowdstrike.py
```

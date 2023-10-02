# Pangea Python SDK examples

This is a quick example about how you use Pangea Python SDK, set up and run it.

## Set up

On this example root directory (./examples/file_scan) run

```
poetry install
```

Set up environment variables ([Instructions](https://pangea.cloud/docs/getting-started/integrate/#set-environment-variables)) `PANGEA_FILE_SCAN_TOKEN` and `PANGEA_DOMAIN` with your project token configured on Pangea User Console (token should have access to File Scan service [Instructions](https://pangea.cloud/docs/getting-started/configure-services/#configure-a-pangea-service)) and with your pangea domain.

## Run

To run examples:
```
poetry run python file_scan_examples/file_scan_async.py
```

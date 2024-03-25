# AuthZ examples

This is a quick example of how to use the Pangea Python SDK to call the AuthZ
service.

## Set up

In the example root directory (`./examples/authz`), run the following command:

```bash
$ poetry install
```

Set up the environment variables ([Instructions][set-environment-variables])
`PANGEA_AUTHZ_TOKEN` and `PANGEA_DOMAIN` with your project token configured on
the Pangea User Console (token should have access to the AuthZ service, see
["Configure a Pangea service"][configure-a-pangea-service]) and with your Pangea
domain.

## Run

To run the example:

```bash
$ poetry run python authz_examples/example.py
```

[configure-a-pangea-service]: https://pangea.cloud/docs/getting-started/configure-services/#configure-a-pangea-service
[set-environment-variables]: https://pangea.cloud/docs/getting-started/integrate/#set-environment-variables

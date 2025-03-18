# AuthZ examples

This is a quick example of how to use the Pangea Python SDK to call the AuthZ
service.

## Set up

In the example root directory (`./examples/authz`), run the following command:

```bash
$ poetry install
```

Set up the environment variables ([Instructions][set-your-environment-variables])
`PANGEA_AUTHZ_TOKEN` and `PANGEA_URL_TEMPLATE` with your project token configured on
the Pangea User Console (token should have access to the AuthZ service, see
[the Tokens page][tokens]) and with your Pangea base url template.

## Run

To run the example:

```bash
$ poetry run python authz_examples/example.py
```

[set-your-environment-variables]: https://pangea.cloud/docs/authz/#set-your-environment-variables
[tokens]: https://pangea.cloud/docs/admin-guide/tokens

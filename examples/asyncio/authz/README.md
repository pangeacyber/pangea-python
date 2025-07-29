# Async AuthZ examples

This is a quick example of how to use the Pangea Python SDK to call the AuthZ
service.

Set up the environment variables ([Instructions][set-your-environment-variables])
`PANGEA_AUTHZ_TOKEN` and `PANGEA_DOMAIN` with your project token configured on
the Pangea User Console (token should have access to the AuthZ service, see
[the Tokens page][tokens]) and with your Pangea domain.

To run the example:

```bash
uv run authz_examples/example.py
```

[set-your-environment-variables]: https://pangea.cloud/docs/authz/#set-your-environment-variables
[tokens]: https://pangea.cloud/docs/admin-guide/tokens

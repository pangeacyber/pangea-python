# Pangea Python SDK examples

This is a quick example of how to set up and use the Pangea Python SDK.

Set up the environment variables ([Instructions](https://pangea.cloud/docs/vault/#set-your-environment-variables)) `PANGEA_VAULT_TOKEN` and `PANGEA_DOMAIN` with your project token configured on the Pangea User Console (token should have access to Vault service [Instructions](https://pangea.cloud/docs/admin-guide/tokens)) and with your Pangea domain. Some examples require
an additional variable `PANGEA_AUDIT_TOKEN_VAULT_ID` that is the Vault ID of a
Secure Audit Log token.

To run an example, use the following command:

```bash
uv run vault_examples/encrypt.py
```

Where `vault_examples/encrypt.py` can be replaced with the desired example.

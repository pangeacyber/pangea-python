from os import getenv

from pangea.config import PangeaConfig
from pangea.services import Audit

# Pull token and domain from environment variables.
token = getenv("PANGEA_AUDIT_MULTICONFIG_TOKEN")
assert token
url_template = getenv("PANGEA_URL_TEMPLATE")
assert url_template
config_id = getenv("PANGEA_AUDIT_AUTH0_CONFIG_ID")
assert config_id

# Set up configuration and the Secure Audit Log client.
config = PangeaConfig(base_url_template=url_template)
audit = Audit(token, config=config, config_id=config_id)


def main():
    # The structure of the data will vary by provider, so below we mimic Auth0's.
    data = {
        "logs": [
            {
                "log_id": "some log ID",
                "data": {
                    "date": "2024-03-29T17:26:50.193Z",
                    "type": "sapi",
                    "description": "Create a log stream",
                    "client_id": "some client ID",
                    "ip": "127.0.0.1",
                    "user_agent": "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0",
                    "user_id": "some user ID",
                },
            }
            # ...
        ]
    }

    # Send data to Pangea.
    audit.log_stream(data)


if __name__ == "__main__":
    main()

import os

from pangea.config import PangeaConfig
from pangea.services import Audit

token = os.getenv("AUDIT_AUTH_TOKEN")
config_id = os.getenv("AUDIT_CONFIG_ID")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(base_domain=domain, config_id=config_id)
audit = Audit(token, config=config)

data = {
    "message": "Hello, World!",
}


def main():
    print(f"Logging: {data['message']}")
    log_response = audit.log(data)

    if log_response.success:
        print(f"Response: {log_response.result}")
    else:
        print(f"Log Request Error: {log_response.response.text}")
        if log_response.result and log_response.result.errors:
            for err in log_response.result.errors:
                print(f"\t{err.detail}")
            print("")

if __name__ == "__main__":
    main()

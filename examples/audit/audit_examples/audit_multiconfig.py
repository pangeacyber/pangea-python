import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import Audit
from pangea.tools import logger_set_pangea_config

token = os.getenv("PANGEA_AUDIT_MULTICONFIG_TOKEN")
config_id = os.getenv("PANGEA_AUDIT_CONFIG_ID")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)

# Set config_id in service constructor
audit = Audit(token, config=config, logger_name="audit", config_id=config_id)

logger_set_pangea_config(logger_name=audit.logger.name)

# This example shows how to perform an audit log


def main():
    msg = "Hello, World!"
    print(f"Logging: {msg}")

    try:
        log_response = audit.log(message=msg, verbose=True)
        print(f"Envelope: {log_response.result.envelope}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import FileIntel
from pangea.tools_util import logger_set_pangea_config

token = os.getenv("PANGEA_INTEL_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
intel = FileIntel(token, config=config, logger_name="intel")
logger_set_pangea_config(logger_name=intel.logger.name)


def main():
    print(f"Checking file...")

    try:
        response = intel.filepathReputation(
            filepath="./pyproject.toml",
            provider="reversinglabs",
            verbose=True,
            raw=True,
        )
        print(f"Response: {response.result}")
    except pe.PangeaAPIException as e:
        print(e)


if __name__ == "__main__":
    main()

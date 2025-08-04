import os
import sys
from pathlib import Path

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import FileIntel
from pangea.tools import logger_set_pangea_config

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from intel_examples.utils import print_reputation_data

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
intel = FileIntel(token, config=config, logger_name="intel")
logger_set_pangea_config(logger_name=intel.logger.name)


def main():
    print("Checking file...")

    try:
        response = intel.filepath_reputation(
            filepath="./pyproject.toml",
            provider="reversinglabs",
            verbose=True,
            raw=True,
        )
        print("Result:")
        print_reputation_data("hash", response.result.data)
    except pe.PangeaAPIException as e:
        print(e)


if __name__ == "__main__":
    main()

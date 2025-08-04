# Retrieve reputation scores for a list of file hashes.

from __future__ import annotations

import os
import sys
from pathlib import Path

from pangea.config import PangeaConfig
from pangea.services import FileIntel
from pangea.tools import logger_set_pangea_config

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from intel_examples.utils import print_reputation_bulk_data

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
intel = FileIntel(token, config=config, logger_name="intel")
logger_set_pangea_config(logger_name=intel.logger.name)


def main() -> None:
    print("Checking file...")
    response = intel.filepath_reputation_bulk(
        filepaths=["./README.md", "./pyproject.toml"],
        provider="reversinglabs",
        verbose=True,
        raw=True,
    )
    assert response.result

    print("Result:")
    print_reputation_bulk_data(response.result.data)


if __name__ == "__main__":
    main()

# Retrieve reputation scores for a list of file hashes.

import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import FileIntel
from pangea.tools import logger_set_pangea_config

from intel_examples.utils import print_reputation_bulk_data

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
url_template = os.getenv("PANGEA_URL_TEMPLATE")
assert url_template
config = PangeaConfig(base_url_template=url_template)
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

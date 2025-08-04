import os
import sys
from pathlib import Path

import pangea.exceptions as pe
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


def main():
    print("Checking hashes...")

    try:
        hash_list = [
            "142b638c6a60b60c7f9928da4fb85a5a8e1422a9ffdc9ee49e17e56ccca9cf6e",
            "179e2b8a4162372cd9344b81793cbf74a9513a002eda3324e6331243f3137a63",
        ]
        response = intel.hash_reputation_bulk(
            hashes=hash_list,
            hash_type="sha256",
            provider="reversinglabs",
            verbose=True,
            raw=True,
        )
        print("Result:")
        print_reputation_bulk_data(response.result.data)
    except pe.PangeaAPIException as e:
        print(e)


if __name__ == "__main__":
    main()

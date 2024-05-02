import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import FileScan
from pangea.tools import logger_set_pangea_config

token = os.getenv("PANGEA_FILE_SCAN_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain

# To enable sync mode, set queue_retry_enable to true and set a timeout
config = PangeaConfig(domain=domain, queued_retry_enabled=True, poll_result_timeout=120)
client = FileScan(token, config=config, logger_name="pangea")
logger_set_pangea_config(logger_name=client.logger.name)

FILEPATH = "./file_scan_examples/testfile.pdf"


def main() -> None:
    print("Checking file...")

    try:
        with open(FILEPATH, "rb") as f:
            response = client.file_scan(file=f, verbose=True, provider="reversinglabs")
            print(f"Response: {response.result}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

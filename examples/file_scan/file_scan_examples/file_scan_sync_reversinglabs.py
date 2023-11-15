import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import FileScan
from pangea.tools import logger_set_pangea_config

token = os.getenv("PANGEA_FILE_SCAN_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
# To work synchronously, it is necessary to set queue_retry_enable to True and set up a proper timeout.
# If the timeout is too short, the service will not return the results and will return an AcceptedRequestException.
config = PangeaConfig(domain=domain, queued_retry_enabled=True, poll_result_timeout=120)
client = FileScan(token, config=config, logger_name="pangea")
logger_set_pangea_config(logger_name=client.logger.name)

FILEPATH = "./file_scan_examples/testfile.pdf"


def main():
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

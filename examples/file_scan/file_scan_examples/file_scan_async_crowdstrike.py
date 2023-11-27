import os
import time

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import FileScan
from pangea.tools import logger_set_pangea_config

token = os.getenv("PANGEA_FILE_SCAN_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")

# To work asynchronously, it is necessary to set queue_retry_enable to False.
# When we call .scan() it will return an AcceptedRequestException immediately if the server returns a 202 response.
config = PangeaConfig(domain=domain, queued_retry_enabled=False)
client = FileScan(token, config=config, logger_name="pangea")
logger_set_pangea_config(logger_name=client.logger.name)

FILEPATH = "./file_scan_examples/testfile.pdf"


def main():
    print("Checking file...")
    exception = None
    try:
        with open(FILEPATH, "rb") as f:
            response = client.file_scan(file=f, verbose=True, provider="crowdstrike")

        print("Scan success on first attempt...")
        print(f"Response: {response.result}")
        exit()
    except pe.AcceptedRequestException as e:
        # Save the exception value to request the results later.
        exception = e
        print("This is a expected exception")
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")
    except pe.PangeaAPIException as e:
        print("This is a unexcepted exception")
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")
        return

    print("We are going to sleep some time before we poll result...")
    # Wait a set amount of time for the results to be ready and then poll for the results.
    time.sleep(20)

    try:
        # poll result, hopefully this should be ready
        response = client.poll_result(exception)
        print("Got result successfully...")
        print(f"Response: {response.result}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

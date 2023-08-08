import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import FileScan

token = os.getenv("PANGEA_INTEL_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
# To work in sync it's need to set up queue_retry_enable to true and set up a proper timeout
# If timeout it's so little service won't end up and will return an AcceptedRequestException anyway
config = PangeaConfig(domain=domain, queued_retry_enabled=True, poll_result_timeout=120)
intel = FileScan(token, config=config)

FILEPATH = "./intel_examples/file_scan/testfile.pdf"


def main():
    print("Checking file...")

    try:
        with open(FILEPATH, "rb") as f:
            response = intel.file_scan(file=f, verbose=True, provider="reversinglabs")
            print(f"Response: {response.result}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

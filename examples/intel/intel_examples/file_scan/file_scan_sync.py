import os
from io import BytesIO

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import FileScan

token = os.getenv("PANGEA_INTEL_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
# To work in sync it's need to set up queue_retry_enable to true and set up a proper timeout
# If timeout it's so little service won't end up and will return an AcceptedRequestException anyway
config = PangeaConfig(domain=domain, queued_retry_enabled=True, poll_result_timeout=120)
intel = FileScan(token, config=config)

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n"


def eicar():
    bio = BytesIO()
    bio.write(EICAR)
    bio.seek(0)
    return bio


def main():
    print(f"Checking file...")

    try:
        response = intel.file_scan(file=eicar(), verbose=True, provider="reversinglabs")
        print(f"Response: {response.result}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

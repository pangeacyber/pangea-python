import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import FileIntel

token = os.getenv("PANGEA_FILE_INTEL_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
intel = FileIntel(token, config=config)


def main():
    print(f"Checking file...")

    try:
        response = intel.lookup(
            hash="142b638c6a60b60c7f9928da4fb85a5a8e1422a9ffdc9ee49e17e56ccca9cf6e",
            hash_type="sha256",
            provider="reversinglabs",
            verbose=True,
            raw=True,
        )
        print(f"Response: {response.result}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

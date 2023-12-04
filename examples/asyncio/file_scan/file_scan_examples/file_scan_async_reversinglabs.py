import asyncio
import os
import time

import pangea.exceptions as pe
from pangea.asyncio.services import FileScanAsync
from pangea.config import PangeaConfig
from pangea.tools import logger_set_pangea_config

token = os.getenv("PANGEA_FILE_SCAN_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")

# To work asynchronously, it is necessary to set queue_retry_enable to False.
# When we call .scan() it will return an AcceptedRequestException immediately if the server returns a 202 response.
config = PangeaConfig(domain=domain, queued_retry_enabled=False)
client = FileScanAsync(token, config=config, logger_name="pangea")
logger_set_pangea_config(logger_name=client.logger.name)

FILEPATH = "./file_scan_examples/testfile.pdf"


async def main():
    print("Checking file...")
    exception = None
    try:
        with open(FILEPATH, "rb") as f:
            response = await client.file_scan(file=f, verbose=True, provider="reversinglabs")

        print("Scan success on first attempt...")
        print(f"Response: {response.result}")
        await client.close()
        exit()
    except pe.AcceptedRequestException as e:
        # Save exception value to request result later
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
    # wait some time to get result ready and poll it
    await asyncio.sleep(20)

    try:
        # poll result, hopefully this should be ready
        response = await client.poll_result(exception)
        print("Got result successfully...")
        print(f"Response: {response.result}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")

    await client.close()


if __name__ == "__main__":
    asyncio.run(main())

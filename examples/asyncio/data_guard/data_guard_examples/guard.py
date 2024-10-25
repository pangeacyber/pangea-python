from __future__ import annotations

import asyncio
import os

from pangea import PangeaConfig
from pangea.asyncio.services.data_guard import DataGuard

token = os.getenv("PANGEA_DATA_GUARD_TOKEN", "")
domain = os.getenv("PANGEA_DOMAIN", "aws.us.pangea.cloud")

data_guard = DataGuard(token, config=PangeaConfig(domain=domain))


async def main() -> None:
    # Text guard.
    input_text = "This email address, security@pangea.cloud, will be redacted."
    print("Guarding text:", input_text)
    text_response = await data_guard.guard_text(input_text)
    assert text_response.result
    print("Response:", text_response.result.redacted_prompt)


if __name__ == "__main__":
    asyncio.run(main())

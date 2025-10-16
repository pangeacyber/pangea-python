from __future__ import annotations

import asyncio
import os

from pangea import PangeaConfig
from pangea.asyncio.services import AIGuardAsync

token = os.getenv("PANGEA_AI_GUARD_TOKEN", "")
domain = os.getenv("PANGEA_DOMAIN", "aws.us.pangea.cloud")


async def main() -> None:
    async with AIGuardAsync(token, config=PangeaConfig(domain=domain)) as ai_guard:
        response = await ai_guard.guard(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "What's in this image?"},
                            {"type": "image_url", "image_url": "https://pangea.cloud/docs/img/favicon.ico"},
                        ],
                    }
                ]
            }
        )
        assert response.result
        print("Result:", response.result)


if __name__ == "__main__":
    asyncio.run(main())

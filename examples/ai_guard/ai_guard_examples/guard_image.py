from __future__ import annotations

import os

from pangea import PangeaConfig
from pangea.services.ai_guard import AIGuard

token = os.getenv("PANGEA_AI_GUARD_TOKEN", "")
domain = os.getenv("PANGEA_DOMAIN", "aws.us.pangea.cloud")

ai_guard = AIGuard(token, config=PangeaConfig(domain=domain))


response = ai_guard.guard(
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

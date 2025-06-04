from __future__ import annotations

import os

from pangea import PangeaConfig
from pangea.services.ai_guard import AIGuard, Message

token = os.getenv("PANGEA_AI_GUARD_TOKEN", "")
domain = os.getenv("PANGEA_DOMAIN", "aws.us.pangea.cloud")

ai_guard = AIGuard(token, config=PangeaConfig(domain=domain))

# Text guard.
input_text = "This email address, security@pangea.cloud, will be redacted."
print("Guarding text:", input_text)
text_response = ai_guard.guard_text(input_text)
assert text_response.result
print("Response:", text_response.result.prompt_text)

# Structured input.
structured_input = [Message(role="user", content="hello world")]
print("Guarding structured input:", structured_input)
structured_response = ai_guard.guard_text(messages=structured_input)
assert structured_response.result
print("Response:", structured_response.result.prompt_messages)

from __future__ import annotations

import os

from pangea import PangeaConfig
from pangea.services.data_guard import DataGuard

token = os.getenv("PANGEA_DATA_GUARD_TOKEN", "")
domain = os.getenv("PANGEA_DOMAIN", "aws.us.pangea.cloud")

data_guard = DataGuard(token, config=PangeaConfig(domain=domain))

# Text guard.
input_text = "This email address, security@pangea.cloud, will be redacted."
print("Guarding text:", input_text)
text_response = data_guard.guard_text(input_text)
assert text_response.result
print("Response:", text_response.result.redacted_prompt)

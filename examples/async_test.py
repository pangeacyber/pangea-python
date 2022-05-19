import os
from pangea.config import PangeaConfig
from pangea.services import Tester


token = os.getenv("PANGEA_TOKEN")
config = PangeaConfig(base_domain="dev.pangea.cloud")
tester = Tester(token=token, config=config)

data = {"echo": "hello world", "delay": 5}
response = tester.async_call(data)

print("TEST RESPONSE:", response.result)

import os
from pangea.config import PangeaConfig
from pangea.services import Locate

token = os.getenv("PANGEA_TOKEN")
config = PangeaConfig(base_domain="dev.pangea.cloud")
locate = Locate(token=token, config=config)

res = locate.geolocate("2.2.2.2")

print("LOG", res.result)

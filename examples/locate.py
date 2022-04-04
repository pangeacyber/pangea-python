from pangea.services import Locate

locate = Locate(token="USERTOKEN")

res = locate.geolocate("2.2.2.2")

print("LOG", res.result)

from pangea.services import Tester

data = {"echo": "hello world", "delay": 5}
tester = Tester(token="USERTOKEN")

test_resp = tester.async_call(data)

print("TEST RESPONSE:", test_resp.result)

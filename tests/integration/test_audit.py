import os
import time
import unittest

from pangea import PangeaConfig
from pangea.services import Audit


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.token = os.getenv("PANGEA_TEST_INTEGRATION_TOKEN")
        config_id = os.getenv("AUDIT_INTEGRATION_CONFIG_TOKEN")
        domain = os.getenv("PANGEA_TEST_INTEGRATION_ENDPOINT")
        self.config = PangeaConfig(domain=domain, config_id=config_id)
        self.audit = Audit(self.token, config=self.config)

    def test_log(self):
        timestamp = time.time()
        event = {"message": f"test-log-{timestamp}"}
        response = self.audit.log(event)
        self.assertEqual(response.code, 200)

    def test_log_signature(self):
        audit = Audit(
            self.token,
            config=self.config,
            enable_signing=True,
            private_key_file="./tests/testdata/privkey",
            verify_response=True,
        )

        msg = "sigtest100"
        event = {}
        event["message"] = msg
        event["actor"] = "Actor"
        event["action"] = "Action"
        event["source"] = "Source"
        event["status"] = "Status"
        event["target"] = "Target"
        event["new"] = "New"
        event["old"] = "Old"

        response = audit.log(event, signing=True, verbose=True)
        self.assertEqual(response.code, 200)

        print(f'Event signature: {response.result["envelope"]["signature"]}')
        print(f'Encoded public key: {response.result["envelope"]["public_key"]}')

        response_search = audit.search(query=f"message: {msg}", verify_signatures=True, limit=1)
        self.assertEqual(response_search.code, 200)

    def test_search_results(self):
        response_search = self.audit.search(query="")
        self.assertEqual(response_search.code, 200)

        response_results = self.audit.results(id=response_search.result.id)
        self.assertEqual(response_results.code, 200)

    def test_root(self):
        response = self.audit.root()
        self.assertEqual(response.code, 200)

        # TODO: Check for a root value

    def test_search_verify(self):
        query = "message:test"
        restriction = {"source": ["monitor"]}
        response = self.audit.search(query=query, restriction=restriction, verify=True)

        self.assertEqual(response.code, 200)

        # TODO: Check membership/consistency verification

    def test_search_sort(self):
        timestamp = time.time()
        query = f"message:test-{timestamp}"
        authors = ["alex", "bob", "chris", "david", "evan"]

        for idx in range(0, 5):
            data = {"message": f"test-{timestamp}", "actor": authors[idx]}
            resp = self.audit.log(data)
            self.assertEqual(resp.code, 200)

        response_desc = self.audit.search(query=query, order="desc", order_by="actor")
        self.assertEqual(response_desc.code, 200)

        response_asc = self.audit.search(query=query, order="asc", order_by="actor")
        self.assertEqual(response_asc.code, 200)

        # TODO: check order of events desc vs asc


if __name__ == "__main__":
    unittest.main()

import os
import time
import unittest

from pangea import PangeaConfig
from pangea.response import PangeaResponse, ResponseStatus
from pangea.services import Audit
from pangea.services.audit import (
    Event,
    LogOutput,
    RootInput,
    SearchInput,
    SearchOrder,
    SearchOrderBy,
    SearchOutput,
    SearchResultInput,
)


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.token = os.getenv("PANGEA_TEST_INTEGRATION_TOKEN")
        config_id = os.getenv("AUDIT_INTEGRATION_CONFIG_TOKEN")
        domain = os.getenv("PANGEA_TEST_INTEGRATION_ENDPOINT")
        self.config = PangeaConfig(domain=domain, config_id=config_id)
        self.audit = Audit(self.token, config=self.config)

    def test_log(self):
        # TODO: complete all field for example
        timestamp = time.time()
        event = {"message": f"test-log-{timestamp}"}
        response: PangeaResponse[LogOutput] = self.audit.log(event, verbose=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        print(type(response.result.envelope.received_at))

    def test_log_signature(self):
        audit = Audit(
            self.token,
            config=self.config,
            enable_signing=True,
            private_key_file="./tests/testdata/privkey",
            verify_response=True,
        )

        msg = "sigtest100"
        event = Event(
            message=msg,
            actor="Actor",
            action="Action",
            source="Source",
            status="Status",
            target="Target",
            new="New",
            old="Old",
        )

        response = audit.log(event, signing=True, verbose=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)

        print(f"Event signature: {response.result.envelope.signature}")
        print(f"Encoded public key: {response.result.envelope.public_key}")

        search_input = SearchInput(query=f"message: {msg}", limit=1)

        response_search = audit.search(search_input, verify_signatures=True)
        self.assertEqual(response_search.status, ResponseStatus.SUCCESS)

    def test_search_results(self):
        response_search = self.audit.search(input=SearchInput(query="", limit=10))
        self.assertEqual(response_search.status, ResponseStatus.SUCCESS)

        response_results = self.audit.results(input=SearchResultInput(id=response_search.result.id))
        self.assertEqual(response_results.status, ResponseStatus.SUCCESS)

        # TODO: check something...

    def test_root(self):
        response = self.audit.root(input=RootInput(tree_size=4))
        self.assertEqual(response.status, ResponseStatus.SUCCESS)

        # TODO: Check for a root value

    def test_search_verify(self):
        query = "message:test"
        restriction = {"source": ["monitor"]}
        input = SearchInput(query=query, search_restriction=restriction)
        response = self.audit.search(input=input, verify=True)

        self.assertEqual(response.status, ResponseStatus.SUCCESS)

        # TODO: Check membership/consistency verification

    def test_search_sort(self):
        timestamp = time.time()
        msg = f"test-{timestamp}"
        authors = ["alex", "bob", "chris", "david", "evan"]

        for idx in range(0, len(authors)):
            event = Event(message=msg, actor=authors[idx])
            resp = self.audit.log(event)
            self.assertEqual(resp.status, ResponseStatus.SUCCESS)

        query = "message:" + msg
        search_input = SearchInput(
            query=query, order=SearchOrder.DESC, order_by=SearchOrderBy.RECEIVED_AT, limit=len(authors)
        )
        r_desc: PangeaResponse[SearchOutput] = self.audit.search(input=search_input)
        self.assertEqual(r_desc.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(r_desc.result.events), len(authors))

        for idx in range(0, len(authors)):
            self.assertEqual(r_desc.result.events[idx].envelope.event.actor, authors[idx])

        search_input.order = SearchOrder.ASC
        r_asc = self.audit.search(input=search_input)
        self.assertEqual(r_asc.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(r_asc.result.events), len(authors))

        for idx in range(0, len(authors)):
            self.assertEqual(r_asc.result.events[len(authors) - 1 - idx].envelope.event.actor, authors[idx])


if __name__ == "__main__":
    unittest.main()

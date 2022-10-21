import os
import time
import unittest

import pangea.exceptions as pexc
from pangea import PangeaConfig
from pangea.response import PangeaResponse, ResponseStatus
from pangea.services import Audit
from pangea.services.audit.models import EventVerification, LogOutput, SearchOrder, SearchOrderBy, SearchOutput


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.token = os.getenv("PANGEA_TEST_INTEGRATION_TOKEN")
        config_id = os.getenv("AUDIT_INTEGRATION_CONFIG_TOKEN")
        domain = os.getenv("PANGEA_TEST_INTEGRATION_ENDPOINT")
        self.config = PangeaConfig(domain=domain, config_id=config_id)
        self.audit = Audit(self.token, config=self.config)

    def test_log(self):
        timestamp = time.time()
        msg = f"test-log-{timestamp}"
        limit = 1

        response: PangeaResponse[LogOutput] = self.audit.log(message=msg, verify=True, verbose=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        receive_at = response.result.envelope.received_at

        response_search: PangeaResponse[SearchOutput] = self.audit.search(
            query=f"message: {msg}", limit=limit, verify_events=True
        )
        self.assertEqual(response_search.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response_search.result.events), limit)
        self.assertEqual(
            response_search.result.events[0].signature_verification, EventVerification.NONE.value
        )  # This message has no signature
        self.assertEqual(response_search.result.events[0].envelope.received_at, receive_at)

    def test_log_signature(self):
        audit = Audit(
            self.token,
            config=self.config,
            private_key_file="./tests/testdata/privkey",
        )

        msg = "sigtest100"

        response = audit.log(
            message=msg,
            actor="Actor",
            action="Action",
            source="Source",
            status="Status",
            target="Target",
            new="New",
            old="Old",
            signing=True,
            verbose=True,
            verify=True,
        )
        receive_at = response.result.envelope.received_at
        self.assertEqual(response.status, ResponseStatus.SUCCESS)

        response_search: PangeaResponse[SearchOutput] = audit.search(
            query=f"message: {msg}", limit=1, verify_events=True
        )
        self.assertEqual(response_search.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response_search.result.events), 1)
        self.assertEqual(
            response_search.result.events[0].envelope.signature,
            "dg7Wg+E8QzZzhECzQoH3v3pbjWObR8ve7SHREAyA9JlFOusKPHVb16t5D3rbscnv80ry/aWzfMTscRNSYJFzDA==",
        )
        self.assertEqual(
            response_search.result.events[0].envelope.public_key, "lvOyDMpK2DQ16NI8G41yINl01wMHzINBahtDPoh4+mE="
        )
        self.assertEqual(response_search.result.events[0].signature_verification, EventVerification.PASS.value)
        self.assertEqual(response_search.result.events[0].envelope.received_at, receive_at)

    def test_log_json(self):
        audit = Audit(
            self.token,
            config=self.config,
            private_key_file="./tests/testdata/privkey",
        )

        msg = {"customtag1": "mycustommsg1", "ct2": "cm2"}
        new = {"customtag3": "mycustommsg3", "ct4": "cm4"}
        old = {"customtag5": "mycustommsg5", "ct6": "cm6"}

        try:
            response = audit.log(
                message=msg,
                actor="Actor",
                action="Action",
                source="Source",
                status="Status",
                target="Target",
                new=new,
                old=old,
                signing=True,
                verbose=True,
                verify=True,
            )
        except pexc.PangeaAPIException as e:
            print(f"Request Error: {e.response.summary}")
            for err in e.errors:
                print(f"\t{err.detail} \n")

        receive_at = response.result.envelope.received_at
        self.assertEqual(response.status, ResponseStatus.SUCCESS)

        response_search: PangeaResponse[SearchOutput] = audit.search(query=f'message:""', limit=1)
        self.assertEqual(response_search.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response_search.result.events), 1)
        self.assertEqual(response_search.result.events[0].signature_verification, EventVerification.PASS.value)
        self.assertEqual(response_search.result.events[0].envelope.received_at, receive_at)

    def test_search_results(self):
        limit = 1
        max_result = 2
        response_search = self.audit.search(query="", limit=limit, max_results=max_result)
        self.assertEqual(response_search.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response_search.result.events), limit)
        self.assertEqual(response_search.result.count, max_result)

        response_results = self.audit.results(id=response_search.result.id, limit=limit, offset=0)
        self.assertEqual(response_results.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response_results.result.events), limit)

        response_results = self.audit.results(id=response_search.result.id, limit=1, offset=1)
        self.assertEqual(response_results.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response_results.result.events), limit)

        try:
            # This should fail because offset is out of range
            response_results = self.audit.results(id=response_search.result.id, limit=1, offset=max_result + 1)
            self.assertEqual(len(response_results.result.events), 0)
        except Exception as e:
            # FIXME: Remove and fix once endpoint is fixed. Have to return error
            self.assertTrue(False)
            self.assertTrue(isinstance(e, pexc.PangeaAPIException))
            print(e)

    def test_root_1(self):
        response = self.audit.root()
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(isinstance(response.result.data.tree_name, str))
        self.assertNotEqual(response.result.data.tree_name, "")
        self.assertTrue(isinstance(response.result.data.root_hash, str))
        self.assertNotEqual(response.result.data.root_hash, "")
        self.assertTrue(isinstance(response.result.data.size, int))
        self.assertTrue(isinstance(response.result.data.url, str))
        self.assertNotEqual(response.result.data.url, "")
        self.assertGreaterEqual(len(response.result.data.consistency_proof), 1)

    def test_root_2(self):
        tree_size = 3
        response = self.audit.root(tree_size=tree_size)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.size, tree_size)

        self.assertTrue(isinstance(response.result.data.tree_name, str))
        self.assertNotEqual(response.result.data.tree_name, "")
        self.assertTrue(isinstance(response.result.data.root_hash, str))
        self.assertNotEqual(response.result.data.root_hash, "")
        self.assertTrue(isinstance(response.result.data.url, str))
        self.assertNotEqual(response.result.data.url, "")
        self.assertGreaterEqual(len(response.result.data.consistency_proof), 1)

    def test_search_verify(self):
        query = "message:Integration test msg"
        response = self.audit.search(
            query=query, order=SearchOrder.DESC, limit=10, max_results=10, verify_consistency=True, verify_events=True
        )

        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        print("events: ", len(response.result.events))
        for idx, search_event in enumerate(response.result.events):
            self.assertEqual(search_event.consistency_verification, EventVerification.PASS)
            self.assertEqual(search_event.membership_verification, EventVerification.PASS)

    def test_search_sort(self):
        timestamp = time.time()
        msg = f"test-{timestamp}"
        authors = ["alex", "bob", "chris", "david", "evan"]

        for idx in range(0, len(authors)):
            resp = self.audit.log(message=msg, actor=authors[idx])
            self.assertEqual(resp.status, ResponseStatus.SUCCESS)

        query = "message:" + msg
        r_desc: PangeaResponse[SearchOutput] = self.audit.search(
            query=query, order=SearchOrder.DESC, order_by=SearchOrderBy.RECEIVED_AT, limit=len(authors)
        )
        self.assertEqual(r_desc.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(r_desc.result.events), len(authors))

        for idx in range(0, len(authors)):
            self.assertEqual(r_desc.result.events[idx].envelope.event.actor, authors[idx])

        r_asc = self.audit.search(
            query=query, order=SearchOrder.ASC, order_by=SearchOrderBy.RECEIVED_AT, limit=len(authors)
        )
        self.assertEqual(r_asc.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(r_asc.result.events), len(authors))

        for idx in range(0, len(authors)):
            self.assertEqual(r_asc.result.events[len(authors) - 1 - idx].envelope.event.actor, authors[idx])


if __name__ == "__main__":
    unittest.main()

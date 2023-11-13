import datetime
import json
import time
import unittest

import pangea.exceptions as pexc
from pangea import PangeaConfig
from pangea.response import PangeaResponse, ResponseStatus
from pangea.services import Audit
from pangea.services.audit.exceptions import AuditException
from pangea.services.audit.models import Event, EventVerification, LogResult, SearchOrder, SearchOrderBy, SearchOutput
from pangea.tools import (
    TestEnvironment,
    get_config_id,
    get_custom_schema_test_token,
    get_multi_config_test_token,
    get_test_domain,
    get_test_token,
    get_vault_signature_test_token,
    logger_set_pangea_config,
)

ACTOR = "python-sdk"
MSG_NO_SIGNED = "test-message"
MSG_JSON = "JSON-message"
MSG_SIGNED_LOCAL = "sign-test-local"
MSG_SIGNED_VAULT = "sign-test-vault"
MSG_CUSTOM_SCHEMA_NO_SIGNED = "python-sdk-custom-schema-no-signed"
JSON_CUSTOM_SCHEMA_NO_SIGNED = "python-sdk-json-custom-schema-no-signed"
MSG_CUSTOM_SCHEMA_SIGNED_LOCAL = "python-sdk-custom-schema-sign-local"
MSG_CUSTOM_SCHEMA_SIGNED_VAULT = "python-sdk-custom-schema-sign-vault"
STATUS_NO_SIGNED = "no-signed"
STATUS_SIGNED = "signed"
LONG_FIELD = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed lacinia, orci eget commodo commodo non."

TEST_ENVIRONMENT = TestEnvironment.DEVELOP

custom_schema_event = {
    "message": MSG_CUSTOM_SCHEMA_NO_SIGNED,
    "field_int": 1,
    "field_bool": True,
    "field_str_short": STATUS_NO_SIGNED,
    "field_str_long": LONG_FIELD,
    "field_time": datetime.datetime.now(),
}


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.general_token = get_test_token(TEST_ENVIRONMENT)
        self.custom_schema_token = get_custom_schema_test_token(TEST_ENVIRONMENT)
        self.vault_token = get_vault_signature_test_token(TEST_ENVIRONMENT)
        self.multi_config_token = get_multi_config_test_token(TEST_ENVIRONMENT)
        self.custom_schema_token = get_custom_schema_test_token(TEST_ENVIRONMENT)

        self.domain = get_test_domain(TEST_ENVIRONMENT)
        self.config = PangeaConfig(domain=self.domain)
        self.audit_general = Audit(self.general_token, config=self.config, logger_name="pangea")
        self.audit_local_sign = Audit(
            self.general_token, config=self.config, private_key_file="./tests/testdata/privkey", logger_name="pangea"
        )
        self.audit_vault_sign = Audit(self.vault_token, config=self.config, logger_name="pangea")
        logger_set_pangea_config(logger_name=self.audit_general.logger.name)

        self.auditCustomSchema = Audit(
            self.custom_schema_token,
            config=PangeaConfig(self.domain),
            logger_name="pangea",
        )

        self.auditCustomSchemaLocalSign = Audit(
            self.custom_schema_token,
            config=PangeaConfig(domain=self.domain),
            private_key_file="./tests/testdata/privkey",
            logger_name="pangea",
        )

    def test_log_no_verbose(self):
        response: PangeaResponse[LogResult] = self.audit_general.log(
            message=MSG_NO_SIGNED, actor=ACTOR, status=STATUS_NO_SIGNED, verbose=False
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.hash)
        self.assertIsNone(response.result.envelope)

    def test_log_tenant_id(self):
        audit = Audit(self.general_token, config=self.config, tenant_id="mytenantid")
        response: PangeaResponse[LogResult] = audit.log(
            message=MSG_NO_SIGNED, actor=ACTOR, status=STATUS_NO_SIGNED, verbose=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.hash)
        self.assertIsNotNone(response.result.envelope)
        event = Event(**response.result.envelope.event)
        self.assertEqual("mytenantid", event.tenant_id)

    def test_log_with_timestamp(self):
        response: PangeaResponse[LogResult] = self.audit_general.log(
            message=MSG_NO_SIGNED,
            actor=ACTOR,
            status=STATUS_NO_SIGNED,
            timestamp=datetime.datetime.now(),
            verbose=False,
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.hash)
        self.assertIsNone(response.result.envelope)

    def test_log_verbose_no_verify(self):
        response: PangeaResponse[LogResult] = self.audit_general.log(
            message=MSG_NO_SIGNED, actor=ACTOR, status=STATUS_NO_SIGNED, verify=False, verbose=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.envelope)
        self.assertIsNone(response.result.consistency_proof)
        self.assertIsNotNone(response.result.membership_proof)
        self.assertEqual(response.result.consistency_verification, EventVerification.NONE)
        self.assertEqual(response.result.membership_verification, EventVerification.NONE)
        self.assertEqual(response.result.signature_verification, EventVerification.NONE)

    def test_log_verify(self):
        response: PangeaResponse[LogResult] = self.audit_general.log(
            message=MSG_NO_SIGNED, actor=ACTOR, status=STATUS_NO_SIGNED, verify=True
        )  # Verify true set verbose to true
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.envelope)
        self.assertIsNone(response.result.consistency_proof)
        self.assertIsNotNone(response.result.membership_proof)
        self.assertEqual(
            response.result.consistency_verification, EventVerification.NONE
        )  # Cant verify consistency on first
        self.assertEqual(response.result.membership_verification, EventVerification.PASS)
        self.assertEqual(response.result.signature_verification, EventVerification.NONE)

        response: PangeaResponse[LogResult] = self.audit_general.log(
            message=MSG_NO_SIGNED, actor=ACTOR, status=STATUS_NO_SIGNED, verify=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.envelope)
        self.assertEqual(response.result.consistency_verification, EventVerification.PASS)  # but second should pass
        self.assertEqual(response.result.membership_verification, EventVerification.PASS)
        self.assertEqual(response.result.signature_verification, EventVerification.NONE)

    def test_log_json(self):
        new = {"customtag3": "mycustommsg3", "ct4": "cm4"}
        old = {"customtag5": "mycustommsg5", "ct6": "cm6"}

        response = self.audit_general.log(
            message=MSG_JSON,
            actor=ACTOR,
            action="Action",
            source="Source",
            status=STATUS_NO_SIGNED,
            target="Target",
            new=new,
            old=old,
            verify=True,
        )

        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.envelope)
        self.assertIsNotNone(response.result.envelope)
        self.assertIsNotNone(response.result.membership_proof)
        self.assertEqual(response.result.membership_verification, EventVerification.PASS)
        self.assertEqual(response.result.signature_verification, EventVerification.NONE)

    def test_log_sign_local_and_verify(self):
        response = self.audit_local_sign.log(
            message=MSG_SIGNED_LOCAL,
            actor=ACTOR,
            action="Action",
            source="Source",
            status=STATUS_SIGNED,
            target="Target",
            new="New",
            old="Old",
            sign_local=True,
            verify=True,
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)

        self.assertIsNotNone(response.result.envelope)
        self.assertIsNone(response.result.consistency_proof)
        self.assertIsNotNone(response.result.membership_proof)
        self.assertEqual(response.result.consistency_verification, EventVerification.NONE)
        self.assertEqual(response.result.membership_verification, EventVerification.PASS)
        self.assertEqual(response.result.signature_verification, EventVerification.PASS)
        self.assertEqual(
            response.result.envelope.public_key,
            r'{"algorithm":"ED25519","key":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAlvOyDMpK2DQ16NI8G41yINl01wMHzINBahtDPoh4+mE=\n-----END PUBLIC KEY-----\n"}',
        )

    def test_sign_without_signer(self):
        def log():
            response: PangeaResponse[LogResult] = self.audit_general.log(
                message=MSG_NO_SIGNED, actor=ACTOR, status=STATUS_NO_SIGNED, verbose=False, sign_local=True
            )

        # This should fail because there is no signed configured
        self.assertRaises(AuditException, log)

    def test_log_sign_vault_and_verify(self):
        response = self.audit_vault_sign.log(
            message=MSG_SIGNED_VAULT,
            actor=ACTOR,
            action="Action",
            source="Source",
            status=STATUS_SIGNED,
            target="Target",
            new="New",
            old="Old",
            verify=True,
        )

        self.assertEqual(response.status, ResponseStatus.SUCCESS)

        self.assertIsNotNone(response.result.envelope)
        self.assertIsNone(response.result.consistency_proof)
        self.assertIsNotNone(response.result.membership_proof)
        self.assertIsNotNone(response.result.envelope.public_key)
        key: dict = json.loads(response.result.envelope.public_key)
        self.assertIsNotNone(key.get("vault_key_id", None))
        self.assertIsNotNone(key.get("vault_key_version", None))
        self.assertIsNotNone(key.get("key", None))
        self.assertIsNotNone(response.result.envelope.signature)
        self.assertEqual(response.result.consistency_verification, EventVerification.NONE)
        self.assertEqual(response.result.membership_verification, EventVerification.PASS)
        self.assertEqual(response.result.signature_verification, EventVerification.PASS)

    def test_log_sign_local_and_tenant_id(self):
        audit = Audit(
            self.general_token,
            config=self.config,
            private_key_file="./tests/testdata/privkey",
            tenant_id="mytenantid",
        )

        response = audit.log(
            message=MSG_SIGNED_LOCAL,
            actor=ACTOR,
            action="Action",
            source="Source",
            status=STATUS_SIGNED,
            target="Target",
            new="New",
            old="Old",
            sign_local=True,
            verify=True,
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)

        self.assertIsNotNone(response.result.envelope)
        self.assertIsNone(response.result.consistency_proof)
        self.assertIsNotNone(response.result.membership_proof)
        self.assertEqual(response.result.consistency_verification, EventVerification.NONE)
        self.assertEqual(response.result.membership_verification, EventVerification.PASS)
        self.assertEqual(response.result.signature_verification, EventVerification.PASS)
        self.assertEqual(
            response.result.envelope.public_key,
            r'{"algorithm":"ED25519","key":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAlvOyDMpK2DQ16NI8G41yINl01wMHzINBahtDPoh4+mE=\n-----END PUBLIC KEY-----\n"}',
        )
        event = Event(**response.result.envelope.event)
        self.assertEqual("mytenantid", event.tenant_id)

    def test_log_json_sign_local_and_verify(self):
        new = {"customtag3": "mycustommsg3", "ct4": "cm4"}
        old = {"customtag5": "mycustommsg5", "ct6": "cm6"}

        response = self.audit_local_sign.log(
            message=MSG_JSON,
            actor=ACTOR,
            action="Action",
            source="Source",
            status=STATUS_NO_SIGNED,
            target="Target",
            new=new,
            old=old,
            sign_local=True,
            verify=True,
        )

        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.envelope)
        self.assertIsNotNone(response.result.envelope)
        self.assertIsNone(response.result.consistency_proof)
        self.assertIsNotNone(response.result.membership_proof)
        self.assertEqual(response.result.membership_verification, EventVerification.PASS)
        self.assertEqual(response.result.signature_verification, EventVerification.PASS)

    def test_log_json_sign_vault_and_verify(self):
        new = {"customtag3": "mycustommsg3", "ct4": "cm4"}
        old = {"customtag5": "mycustommsg5", "ct6": "cm6"}

        response = self.audit_vault_sign.log(
            message=MSG_JSON,
            actor=ACTOR,
            action="Action",
            source="Source",
            status=STATUS_SIGNED,
            target="Target",
            new=new,
            old=old,
            verify=True,
        )

        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.envelope)
        self.assertIsNotNone(response.result.envelope.event)
        self.assertIsNone(response.result.consistency_proof)
        self.assertIsNotNone(response.result.membership_proof)
        self.assertEqual(response.result.membership_verification, EventVerification.PASS)
        self.assertEqual(response.result.signature_verification, EventVerification.PASS)

    # Test custom schema
    def test_custom_schema_log_no_verbose(self):
        response: PangeaResponse[LogResult] = self.auditCustomSchema.log_event(event=custom_schema_event, verbose=False)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.hash)
        self.assertIsNone(response.result.envelope)

    def test_custom_schema_log_verbose_no_verify(self):
        response: PangeaResponse[LogResult] = self.auditCustomSchema.log_event(
            event=custom_schema_event, verify=False, verbose=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.envelope)
        self.assertIsNone(response.result.consistency_proof)
        self.assertIsNotNone(response.result.membership_proof)
        self.assertEqual(response.result.consistency_verification, EventVerification.NONE)
        self.assertEqual(response.result.membership_verification, EventVerification.NONE)
        self.assertEqual(response.result.signature_verification, EventVerification.NONE)

    def test_custom_schema_log_verify(self):
        response: PangeaResponse[LogResult] = self.auditCustomSchema.log_event(
            event=custom_schema_event,
            verify=True,
        )  # Verify true set verbose to true
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.envelope)
        self.assertIsNone(response.result.consistency_proof)
        self.assertIsNotNone(response.result.membership_proof)
        self.assertEqual(
            response.result.consistency_verification, EventVerification.NONE
        )  # Cant verify consistency on first
        self.assertEqual(response.result.membership_verification, EventVerification.PASS)
        self.assertEqual(response.result.signature_verification, EventVerification.NONE)

        response: PangeaResponse[LogResult] = self.auditCustomSchema.log_event(
            event=custom_schema_event,
            verify=True,
        )  # Verify true set verbose to true
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.envelope)
        self.assertEqual(response.result.consistency_verification, EventVerification.PASS)  # but second should pass
        self.assertEqual(response.result.membership_verification, EventVerification.PASS)
        self.assertEqual(response.result.signature_verification, EventVerification.NONE)

    def test_custom_schema_log_json(self):
        jsonfield = {"customtag3": "mycustommsg3", "ct6": "cm6", "ct4": "cm4", "field_int": 2, "field_bool": True}
        event = {
            "message": JSON_CUSTOM_SCHEMA_NO_SIGNED,
            "field_int": 1,
            "field_bool": True,
            "field_str_short": STATUS_NO_SIGNED,
            "field_str_long": jsonfield,
            "field_time": datetime.datetime.now(),
        }

        response: PangeaResponse[LogResult] = self.auditCustomSchema.log_event(
            event=event,
            verify=True,
        )

        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.envelope)
        self.assertIsNotNone(response.result.envelope)
        self.assertIsNotNone(response.result.membership_proof)
        self.assertEqual(response.result.membership_verification, EventVerification.PASS)
        self.assertEqual(response.result.signature_verification, EventVerification.NONE)

    def test_custom_schema_log_sign_local_and_verify(self):
        response: PangeaResponse[LogResult] = self.auditCustomSchemaLocalSign.log_event(
            event=custom_schema_event,
            sign_local=True,
            verify=True,
        )  # Verify true set verbose to true

        self.assertEqual(response.status, ResponseStatus.SUCCESS)

        self.assertIsNotNone(response.result.envelope)
        self.assertIsNone(response.result.consistency_proof)
        self.assertIsNotNone(response.result.membership_proof)
        self.assertEqual(response.result.consistency_verification, EventVerification.NONE)
        self.assertEqual(response.result.membership_verification, EventVerification.PASS)
        self.assertEqual(response.result.signature_verification, EventVerification.PASS)
        self.assertEqual(
            response.result.envelope.public_key,
            r'{"algorithm":"ED25519","key":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAlvOyDMpK2DQ16NI8G41yINl01wMHzINBahtDPoh4+mE=\n-----END PUBLIC KEY-----\n"}',
        )

    def test_custom_schema_log_json_sign_local_and_verify(self):
        jsonfield = {"customtag3": "mycustommsg3", "ct6": "cm6", "ct4": "cm4", "field_int": 2, "field_bool": True}
        event = {
            "message": MSG_CUSTOM_SCHEMA_NO_SIGNED,
            "field_int": 1,
            "field_bool": True,
            "field_str_short": STATUS_NO_SIGNED,
            "field_str_long": jsonfield,
            "field_time": datetime.datetime.now(),
        }

        response: PangeaResponse[LogResult] = self.auditCustomSchemaLocalSign.log_event(
            event=event,
            sign_local=True,
            verify=True,
        )

        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.envelope)
        self.assertIsNotNone(response.result.envelope)
        self.assertIsNotNone(response.result.membership_proof)
        self.assertEqual(response.result.membership_verification, EventVerification.PASS)
        self.assertEqual(response.result.signature_verification, EventVerification.PASS)

    def test_search_results_verbose(self):
        limit = 2
        max_result = 3
        response_search = self.audit_general.search(
            query="message:" + MSG_SIGNED_LOCAL,
            order=SearchOrder.ASC,
            limit=limit,
            max_results=max_result,
            verbose=True,
            start="7d",
        )
        self.assertEqual(response_search.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response_search.result.events), limit)
        self.assertEqual(response_search.result.count, max_result)

        resultsLimit = 2
        # Verify consistency en true
        response_results = self.audit_general.results(
            id=response_search.result.id, limit=resultsLimit, verify_consistency=True
        )
        self.assertEqual(response_results.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response_results.result.events), resultsLimit)
        for event in response_results.result.events:
            self.assertEqual(event.consistency_verification, EventVerification.PASS)
            self.assertEqual(event.membership_verification, EventVerification.PASS)

        # Verify consistency en false
        response_results = self.audit_general.results(
            id=response_search.result.id, limit=resultsLimit, offset=1, verify_consistency=False
        )
        self.assertEqual(response_results.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response_results.result.events), resultsLimit)
        for event in response_results.result.events:
            self.assertEqual(event.consistency_verification, EventVerification.NONE)
            self.assertEqual(event.membership_verification, EventVerification.NONE)

        def resultBadOffset():
            self.audit_general.results(id=response_search.result.id, limit=1, offset=max_result + 1)

        # This should fail because offset is out of range
        self.assertRaises(pexc.BadOffsetException, resultBadOffset)

    def test_search_results_no_verbose(self):
        limit = 5
        max_result = 5
        response_search = self.audit_general.search(
            query='message:""', limit=limit, max_results=max_result, verbose=False
        )
        self.assertEqual(response_search.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response_search.result.events), limit)
        self.assertEqual(response_search.result.count, max_result)

        resultsLimit = 2
        # Verify consistency en true
        response_results = self.audit_general.results(
            id=response_search.result.id, limit=resultsLimit, verify_consistency=True
        )
        self.assertEqual(response_results.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response_results.result.events), resultsLimit)
        for event in response_results.result.events:
            self.assertEqual(event.consistency_verification, EventVerification.NONE)
            self.assertEqual(event.membership_verification, EventVerification.NONE)

        # Verify consistency en false
        response_results = self.audit_general.results(
            id=response_search.result.id, limit=resultsLimit, offset=1, verify_consistency=False
        )
        self.assertEqual(response_results.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response_results.result.events), resultsLimit)
        for event in response_results.result.events:
            self.assertEqual(event.consistency_verification, EventVerification.NONE)
            self.assertEqual(event.membership_verification, EventVerification.NONE)

        def resultBadOffset():
            self.audit_general.results(id=response_search.result.id, limit=1, offset=max_result + 1)

        # This should fail because offset is out of range
        self.assertRaises(pexc.BadOffsetException, resultBadOffset)

    def test_result_bad_offset(self):
        def resultBadOffset():
            self.audit_general.results(id="id", limit=1, offset=-1)

        # This should fail because offset is out of range
        self.assertRaises(AuditException, resultBadOffset)

    def test_result_bad_limit(self):
        def resultBadLimit():
            self.audit_general.results(id="id", limit=-1, offset=1)

        # This should fail because offset is out of range
        self.assertRaises(AuditException, resultBadLimit)

    def test_search_with_dates(self):
        limit = 2
        max_result = 3
        end = datetime.datetime.now()
        start = end - datetime.timedelta(days=30)
        response_search = self.audit_general.search(
            query='message:""',
            order=SearchOrder.DESC,
            limit=limit,
            max_results=max_result,
            verbose=True,
            start=start,
            end=end,
        )
        self.assertEqual(response_search.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response_search.result.events), limit)
        self.assertEqual(response_search.result.count, max_result)

    def test_search_with_dates_as_strings(self):
        limit = 2
        max_result = 3
        end = "0d"
        start = "30d"
        response_search = self.audit_general.search(
            query='message:""',
            order=SearchOrder.DESC,
            limit=limit,
            max_results=max_result,
            verbose=True,
            start=start,
            end=end,
        )
        self.assertEqual(response_search.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response_search.result.events), limit)
        self.assertEqual(response_search.result.count, max_result)

    def test_root_1(self):
        response = self.audit_general.root()
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertTrue(isinstance(response.result.data.tree_name, str))
        self.assertNotEqual(response.result.data.tree_name, "")
        self.assertTrue(isinstance(response.result.data.root_hash, str))
        self.assertNotEqual(response.result.data.root_hash, "")
        self.assertTrue(isinstance(response.result.data.size, int))
        self.assertTrue(isinstance(response.result.data.url, str))
        self.assertNotEqual(response.result.data.url, "")
        if response.result.data.consistency_proof is not None:
            self.assertGreaterEqual(len(response.result.data.consistency_proof), 1)

    def test_root_2(self):
        tree_size = 1
        response = self.audit_general.root(tree_size=tree_size)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(response.result.data.size, tree_size)

        self.assertTrue(isinstance(response.result.data.tree_name, str))
        self.assertNotEqual(response.result.data.tree_name, "")
        self.assertTrue(isinstance(response.result.data.root_hash, str))
        self.assertNotEqual(response.result.data.root_hash, "")
        self.assertTrue(isinstance(response.result.data.url, str))
        self.assertNotEqual(response.result.data.url, "")
        if response.result.data.consistency_proof is not None:
            self.assertGreaterEqual(len(response.result.data.consistency_proof), 1)

    def test_search_verify(self):
        query = f"message:{MSG_SIGNED_LOCAL}"
        response = self.audit_general.search(
            query=query,
            order=SearchOrder.ASC,
            limit=2,
            max_results=2,
            verify_consistency=True,
            verify_events=True,
            start="7d",
        )

        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertNotEqual(0, len(response.result.events))
        for idx, search_event in enumerate(response.result.events):
            self.assertEqual(search_event.consistency_verification, EventVerification.PASS)
            self.assertEqual(search_event.membership_verification, EventVerification.PASS)

    def test_search_sort(self):
        timestamp = time.time()
        msg = f"test-{timestamp}"
        authors = ["alex", "bob", "chris", "david", "evan"]

        for idx in range(0, len(authors)):
            resp = self.audit_general.log(message=msg, actor=authors[idx])
            self.assertEqual(resp.status, ResponseStatus.SUCCESS)

        query = "message:" + msg
        r_desc: PangeaResponse[SearchOutput] = self.audit_general.search(
            query=query, order=SearchOrder.ASC, order_by=SearchOrderBy.RECEIVED_AT, limit=len(authors)
        )
        self.assertEqual(r_desc.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(r_desc.result.events), len(authors))

        for idx in range(0, len(authors)):
            self.assertEqual(r_desc.result.events[idx].envelope.event["actor"], authors[idx])

        r_asc = self.audit_general.search(
            query=query, order=SearchOrder.DESC, order_by=SearchOrderBy.RECEIVED_AT, limit=len(authors)
        )
        self.assertEqual(r_asc.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(r_asc.result.events), len(authors))

        for idx in range(0, len(authors)):
            self.assertEqual(r_asc.result.events[len(authors) - 1 - idx].envelope.event["actor"], authors[idx])

    def test_multi_config_log(self):
        config = PangeaConfig(domain=self.domain)
        audit_multi_config = Audit(self.multi_config_token, config=config)

        def log_without_config_id():
            response: PangeaResponse[LogResult] = audit_multi_config.log(
                message=MSG_NO_SIGNED, actor=ACTOR, status=STATUS_NO_SIGNED, verbose=True
            )

        # This should fail because this token has multi config but we didn't set up a config id
        self.assertRaises(pexc.PangeaAPIException, log_without_config_id)

    def test_multi_config_log_config_1(self):
        config_id = get_config_id(TEST_ENVIRONMENT, "audit", 1)
        config = PangeaConfig(domain=self.domain)
        audit_multi_config = Audit(self.multi_config_token, config=config, config_id=config_id)

        response: PangeaResponse[LogResult] = audit_multi_config.log(
            message=MSG_NO_SIGNED, actor=ACTOR, status=STATUS_NO_SIGNED, verbose=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.hash)
        self.assertIsNotNone(response.result.envelope)

    def test_multi_config_log_config_2(self):
        config_id = get_config_id(TEST_ENVIRONMENT, "audit", 2)
        config = PangeaConfig(domain=self.domain)
        audit_multi_config = Audit(self.multi_config_token, config=config, config_id=config_id)

        response: PangeaResponse[LogResult] = audit_multi_config.log(
            message=MSG_NO_SIGNED, actor=ACTOR, status=STATUS_NO_SIGNED, verbose=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.hash)
        self.assertIsNotNone(response.result.envelope)

    def test_log_bulk(self):
        event = Event(message=MSG_NO_SIGNED, actor=ACTOR, status=STATUS_NO_SIGNED)
        events = [event, event]

        response = self.audit_general.log_bulk(events=events, verbose=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        for result in response.result.results:
            self.assertIsNotNone(result.envelope)
            self.assertIsNotNone(result.envelope.event)
            self.assertEqual(result.envelope.event["message"], MSG_NO_SIGNED)
            self.assertIsNone(result.consistency_proof)
            self.assertEqual(result.consistency_verification, EventVerification.NONE)
            self.assertEqual(result.membership_verification, EventVerification.NONE)
            self.assertEqual(result.signature_verification, EventVerification.NONE)

    def test_log_bulk_async(self):
        event = Event(message=MSG_NO_SIGNED, actor=ACTOR, status=STATUS_NO_SIGNED)
        events = [event, event]

        def log():
            response = self.audit_general.log_bulk_async(events=events, verbose=True)

        # This should return 202
        self.assertRaises(pexc.AcceptedRequestException, log)

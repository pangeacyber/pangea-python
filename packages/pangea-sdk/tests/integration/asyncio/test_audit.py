from __future__ import annotations

import datetime
import json
import logging
import time
import unittest
from asyncio import sleep
from contextlib import suppress

import pangea.exceptions as pe
from pangea import PangeaConfig
from pangea.asyncio.services.audit import AuditAsync
from pangea.response import PangeaResponse, ResponseStatus
from pangea.services.audit.exceptions import AuditException
from pangea.services.audit.models import (
    DownloadFormat,
    Event,
    EventVerification,
    LogResult,
    SearchOrder,
    SearchOrderBy,
    SearchOutput,
)
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
from pangea.utils import format_datetime
from tests.test_tools import load_test_environment

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

TEST_ENVIRONMENT = load_test_environment(AuditAsync.service_name, TestEnvironment.LIVE)

custom_schema_event = {
    "message": MSG_CUSTOM_SCHEMA_NO_SIGNED,
    "field_int": 1,
    "field_bool": True,
    "field_str_short": STATUS_NO_SIGNED,
    "field_str_long": LONG_FIELD,
    "field_time": format_datetime(datetime.datetime.now(tz=datetime.timezone.utc)),
}


class TestAuditAsync(unittest.IsolatedAsyncioTestCase):
    log = logging.getLogger(__name__)

    def setUp(self):
        self.general_token = get_test_token(TEST_ENVIRONMENT)
        self.custom_schema_token = get_custom_schema_test_token(TEST_ENVIRONMENT)
        self.vault_token = get_vault_signature_test_token(TEST_ENVIRONMENT)
        self.multi_config_token = get_multi_config_test_token(TEST_ENVIRONMENT)
        self.custom_schema_token = get_custom_schema_test_token(TEST_ENVIRONMENT)

        self.domain = get_test_domain(TEST_ENVIRONMENT)
        self.config = PangeaConfig(domain=self.domain)
        self.audit_general = AuditAsync(self.general_token, config=self.config, logger_name="pangea")
        self.audit_local_sign = AuditAsync(
            self.general_token, config=self.config, private_key_file="./tests/testdata/privkey", logger_name="pangea"
        )
        self.audit_vault_sign = AuditAsync(self.vault_token, config=self.config, logger_name="pangea")
        logger_set_pangea_config(logger_name=self.audit_general.logger.name)

        self.auditCustomSchema = AuditAsync(
            self.custom_schema_token,
            config=PangeaConfig(domain=self.domain),
            logger_name="pangea",
        )

        self.auditCustomSchemaLocalSign = AuditAsync(
            self.custom_schema_token,
            config=PangeaConfig(domain=self.domain),
            private_key_file="./tests/testdata/privkey",
            logger_name="pangea",
        )

    async def asyncTearDown(self):
        await self.audit_general.close()
        await self.audit_local_sign.close()
        await self.audit_vault_sign.close()
        await self.auditCustomSchema.close()
        await self.auditCustomSchemaLocalSign.close()

    async def test_log_no_verbose(self):
        response: PangeaResponse[LogResult] = await self.audit_general.log(
            message=MSG_NO_SIGNED, actor=ACTOR, status=STATUS_NO_SIGNED, verbose=False
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.hash)
        self.assertIsNone(response.result.envelope)

    async def test_log_tenant_id(self):
        audit = AuditAsync(self.general_token, config=self.config, tenant_id="mytenantid")
        response: PangeaResponse[LogResult] = await audit.log(
            message=MSG_NO_SIGNED, actor=ACTOR, status=STATUS_NO_SIGNED, verbose=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.hash)
        self.assertIsNotNone(response.result.envelope)
        event = Event(**response.result.envelope.event)
        self.assertEqual("mytenantid", event.tenant_id)

        await audit.close()

    async def test_log_with_timestamp(self):
        response: PangeaResponse[LogResult] = await self.audit_general.log(
            message=MSG_NO_SIGNED,
            actor=ACTOR,
            status=STATUS_NO_SIGNED,
            timestamp=datetime.datetime.now(),
            verbose=False,
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.hash)
        self.assertIsNone(response.result.envelope)

    async def test_log_verbose_no_verify(self):
        response: PangeaResponse[LogResult] = await self.audit_general.log(
            message=MSG_NO_SIGNED, actor=ACTOR, status=STATUS_NO_SIGNED, verify=False, verbose=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.envelope)
        self.assertIsNone(response.result.consistency_proof)
        self.assertIsNotNone(response.result.membership_proof)
        self.assertEqual(response.result.consistency_verification, EventVerification.NONE)
        self.assertEqual(response.result.membership_verification, EventVerification.NONE)
        self.assertEqual(response.result.signature_verification, EventVerification.NONE)

    async def test_log_verify(self):
        response: PangeaResponse[LogResult] = await self.audit_general.log(
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

        response: PangeaResponse[LogResult] = await self.audit_general.log(
            message=MSG_NO_SIGNED, actor=ACTOR, status=STATUS_NO_SIGNED, verify=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.envelope)
        self.assertEqual(response.result.consistency_verification, EventVerification.PASS)  # but second should pass
        self.assertEqual(response.result.membership_verification, EventVerification.PASS)
        self.assertEqual(response.result.signature_verification, EventVerification.NONE)

    async def test_log_json(self):
        new = {"customtag3": "mycustommsg3", "ct4": "cm4"}
        old = {"customtag5": "mycustommsg5", "ct6": "cm6"}

        response = await self.audit_general.log(
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

    async def test_log_sign_local_and_verify(self):
        response = await self.audit_local_sign.log(
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

    async def test_sign_without_signer(self):
        with self.assertRaises(AuditException):
            # This should fail because there is no signed configured
            await self.audit_general.log(
                message=MSG_NO_SIGNED, actor=ACTOR, status=STATUS_NO_SIGNED, verbose=False, sign_local=True
            )

    async def test_log_sign_vault_and_verify(self):
        response = await self.audit_vault_sign.log(
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
        self.assertIsNotNone(key.get("vault_key_id"))
        self.assertIsNotNone(key.get("vault_key_version"))
        self.assertIsNotNone(key.get("key"))
        self.assertIsNotNone(response.result.envelope.signature)
        self.assertEqual(response.result.consistency_verification, EventVerification.NONE)
        self.assertEqual(response.result.membership_verification, EventVerification.PASS)
        self.assertEqual(response.result.signature_verification, EventVerification.PASS)

    async def test_log_sign_local_and_tenant_id(self):
        audit = AuditAsync(
            self.general_token,
            config=self.config,
            private_key_file="./tests/testdata/privkey",
            tenant_id="mytenantid",
        )

        response = await audit.log(
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

        await audit.close()

    async def test_log_json_sign_local_and_verify(self):
        new = {"customtag3": "mycustommsg3", "ct4": "cm4"}
        old = {"customtag5": "mycustommsg5", "ct6": "cm6"}

        response = await self.audit_local_sign.log(
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

    async def test_log_json_sign_vault_and_verify(self):
        new = {"customtag3": "mycustommsg3", "ct4": "cm4"}
        old = {"customtag5": "mycustommsg5", "ct6": "cm6"}

        response = await self.audit_vault_sign.log(
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
    async def test_custom_schema_log_no_verbose(self):
        response: PangeaResponse[LogResult] = await self.auditCustomSchema.log_event(
            event=custom_schema_event, verbose=False
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.hash)
        self.assertIsNone(response.result.envelope)

    async def test_custom_schema_log_verbose_no_verify(self):
        response: PangeaResponse[LogResult] = await self.auditCustomSchema.log_event(
            event=custom_schema_event, verify=False, verbose=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.envelope)
        self.assertIsNone(response.result.consistency_proof)
        self.assertIsNotNone(response.result.membership_proof)
        self.assertEqual(response.result.consistency_verification, EventVerification.NONE)
        self.assertEqual(response.result.membership_verification, EventVerification.NONE)
        self.assertEqual(response.result.signature_verification, EventVerification.NONE)

    async def test_custom_schema_log_verify(self):
        response: PangeaResponse[LogResult] = await self.auditCustomSchema.log_event(
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

        response: PangeaResponse[LogResult] = await self.auditCustomSchema.log_event(
            event=custom_schema_event,
            verify=True,
        )  # Verify true set verbose to true
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.envelope)
        self.assertEqual(response.result.consistency_verification, EventVerification.PASS)  # but second should pass
        self.assertEqual(response.result.membership_verification, EventVerification.PASS)
        self.assertEqual(response.result.signature_verification, EventVerification.NONE)

    async def test_custom_schema_log_json(self):
        jsonfield = {"customtag3": "mycustommsg3", "ct6": "cm6", "ct4": "cm4", "field_int": 2, "field_bool": True}
        event = {
            "message": JSON_CUSTOM_SCHEMA_NO_SIGNED,
            "field_int": 1,
            "field_bool": True,
            "field_str_short": STATUS_NO_SIGNED,
            "field_str_long": jsonfield,
            "field_time": datetime.datetime.now(),
        }

        response: PangeaResponse[LogResult] = await self.auditCustomSchema.log_event(
            event=event,
            verify=True,
        )

        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.envelope)
        self.assertIsNotNone(response.result.envelope)
        self.assertIsNotNone(response.result.membership_proof)
        self.assertEqual(response.result.membership_verification, EventVerification.PASS)
        self.assertEqual(response.result.signature_verification, EventVerification.NONE)

    async def test_custom_schema_log_sign_local_and_verify(self):
        response: PangeaResponse[LogResult] = await self.auditCustomSchemaLocalSign.log_event(
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

    async def test_custom_schema_log_json_sign_local_and_verify(self):
        jsonfield = {"customtag3": "mycustommsg3", "ct6": "cm6", "ct4": "cm4", "field_int": 2, "field_bool": True}
        event = {
            "message": MSG_CUSTOM_SCHEMA_NO_SIGNED,
            "field_int": 1,
            "field_bool": True,
            "field_str_short": STATUS_NO_SIGNED,
            "field_str_long": jsonfield,
            "field_time": format_datetime(datetime.datetime.now(tz=datetime.timezone.utc)),
        }

        response: PangeaResponse[LogResult] = await self.auditCustomSchemaLocalSign.log_event(
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

    async def test_search_results_verbose(self):
        limit = 2
        max_result = 3
        response_search = await self.audit_general.search(
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
        response_results = await self.audit_general.results(
            id=response_search.result.id, limit=resultsLimit, verify_consistency=True
        )
        self.assertEqual(response_results.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response_results.result.events), resultsLimit)
        for event in response_results.result.events:
            self.assertEqual(event.consistency_verification, EventVerification.PASS)
            self.assertEqual(event.membership_verification, EventVerification.PASS)

        # Verify consistency en false
        response_results = await self.audit_general.results(
            id=response_search.result.id, limit=resultsLimit, offset=1, verify_consistency=False
        )
        self.assertEqual(response_results.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response_results.result.events), resultsLimit)
        for event in response_results.result.events:
            self.assertEqual(event.consistency_verification, EventVerification.NONE)
            self.assertEqual(event.membership_verification, EventVerification.NONE)

        with self.assertRaises(pe.BadOffsetException):
            # This should fail because offset is out of range
            await self.audit_general.results(id=response_search.result.id, limit=1, offset=max_result + 1)

    async def test_search_results_no_verbose(self) -> None:
        limit = 10
        max_result = 10

        with suppress(pe.AcceptedRequestException):
            response_search = await self.audit_general.search(
                query='message:""', limit=limit, max_results=max_result, verbose=False
            )
            self.assertEqual(response_search.status, ResponseStatus.SUCCESS)
            self.assertEqual(len(response_search.result.events), limit)
            self.assertEqual(response_search.result.count, max_result)

            results_limit = 2
            # Verify consistency en true
            response_results = await self.audit_general.results(
                id=response_search.result.id, limit=results_limit, verify_consistency=True
            )
            self.assertEqual(response_results.status, ResponseStatus.SUCCESS)
            self.assertEqual(len(response_results.result.events), results_limit)
            for event in response_results.result.events:
                self.assertEqual(event.consistency_verification, EventVerification.NONE)
                self.assertEqual(event.membership_verification, EventVerification.NONE)

            # Verify consistency en false
            response_results = await self.audit_general.results(
                id=response_search.result.id, limit=results_limit, offset=1, verify_consistency=False
            )
            self.assertEqual(response_results.status, ResponseStatus.SUCCESS)
            self.assertEqual(len(response_results.result.events), results_limit)
            for event in response_results.result.events:
                self.assertEqual(event.consistency_verification, EventVerification.NONE)
                self.assertEqual(event.membership_verification, EventVerification.NONE)

            with self.assertRaises(pe.BadOffsetException):
                # This should fail because offset is out of range
                await self.audit_general.results(id=response_search.result.id, limit=1, offset=max_result + 1)

    async def test_result_bad_offset(self):
        with self.assertRaises(AuditException):
            # This should fail because offset is out of range
            await self.audit_general.results(id="id", limit=1, offset=-1)

    async def test_result_bad_limit(self):
        with self.assertRaises(AuditException):
            # This should fail because offset is out of range
            await self.audit_general.results(id="id", limit=-1, offset=1)

    async def test_search_with_dates(self):
        limit = 2
        max_result = 3
        end = datetime.datetime.now()
        start = end - datetime.timedelta(days=30)
        response_search = await self.audit_general.search(
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

    async def test_search_with_dates_as_strings(self):
        limit = 2
        max_result = 3
        end = "0d"
        start = "30d"
        response_search = await self.audit_general.search(
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

    async def test_root_1(self):
        response = await self.audit_general.root()
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

    async def test_root_2(self):
        tree_size = 1
        response = await self.audit_general.root(tree_size=tree_size)
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

    async def test_search_verify(self):
        query = f"message:{MSG_SIGNED_LOCAL}"
        response = await self.audit_general.search(
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
        for _idx, search_event in enumerate(response.result.events):
            self.assertEqual(search_event.consistency_verification, EventVerification.PASS)
            self.assertEqual(search_event.membership_verification, EventVerification.PASS)

    async def test_search_sort(self) -> None:
        timestamp = time.time()
        msg = f"test-{timestamp}"
        authors = ["alex", "bob", "chris", "david", "evan"]

        with suppress(pe.AcceptedRequestException):
            for idx in range(len(authors)):
                resp = await self.audit_general.log(message=msg, actor=authors[idx])
                self.assertEqual(resp.status, ResponseStatus.SUCCESS)

            query = "message:" + msg
            r_desc: PangeaResponse[SearchOutput] = await self.audit_general.search(
                query=query, order=SearchOrder.ASC, order_by=SearchOrderBy.RECEIVED_AT, limit=len(authors)
            )
            assert r_desc.result
            self.assertEqual(r_desc.status, ResponseStatus.SUCCESS)
            self.assertEqual(len(r_desc.result.events), len(authors))

            for idx in range(len(authors)):
                self.assertEqual(r_desc.result.events[idx].envelope.event["actor"], authors[idx])

            r_asc = await self.audit_general.search(
                query=query, order=SearchOrder.DESC, order_by=SearchOrderBy.RECEIVED_AT, limit=len(authors)
            )
            self.assertEqual(r_asc.status, ResponseStatus.SUCCESS)
            self.assertEqual(len(r_asc.result.events), len(authors))

            for idx in range(len(authors)):
                self.assertEqual(r_asc.result.events[len(authors) - 1 - idx].envelope.event["actor"], authors[idx])

    async def test_search_custom_schema_order_by(self) -> None:
        limit = 2
        max_result = 3

        with suppress(pe.AcceptedRequestException):
            response_search = await self.auditCustomSchema.search(
                query='message:""',
                order=SearchOrder.DESC,
                order_by="field_int",
                limit=limit,
                max_results=max_result,
                verbose=True,
                end="0d",
                start="30d",
            )
            self.assertEqual(response_search.status, ResponseStatus.SUCCESS)
            self.assertEqual(len(response_search.result.events), limit)
            self.assertEqual(response_search.result.count, max_result)

    async def test_multi_config_log(self):
        config = PangeaConfig(domain=self.domain)
        audit_multi_config = AuditAsync(self.multi_config_token, config=config)

        with self.assertRaises(pe.PangeaAPIException):
            # This should fail because this token has multi config but we didn't set up a config id
            await audit_multi_config.log(message=MSG_NO_SIGNED, actor=ACTOR, status=STATUS_NO_SIGNED, verbose=True)

        await audit_multi_config.close()

    async def test_multi_config_log_config_1(self):
        config_id = get_config_id(TEST_ENVIRONMENT, "audit", 1)
        config = PangeaConfig(domain=self.domain)
        audit_multi_config = AuditAsync(self.multi_config_token, config=config, config_id=config_id)

        response: PangeaResponse[LogResult] = await audit_multi_config.log(
            message=MSG_NO_SIGNED, actor=ACTOR, status=STATUS_NO_SIGNED, verbose=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.hash)
        self.assertIsNotNone(response.result.envelope)

        await audit_multi_config.close()

    async def test_multi_config_log_config_2(self):
        config_id = get_config_id(TEST_ENVIRONMENT, "audit", 2)
        config = PangeaConfig(domain=self.domain)
        audit_multi_config = AuditAsync(self.multi_config_token, config=config, config_id=config_id)

        response: PangeaResponse[LogResult] = await audit_multi_config.log(
            message=MSG_NO_SIGNED, actor=ACTOR, status=STATUS_NO_SIGNED, verbose=True
        )
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response.result.hash)
        self.assertIsNotNone(response.result.envelope)

        await audit_multi_config.close()

    async def test_log_bulk(self):
        event = Event(message=MSG_NO_SIGNED, actor=ACTOR, status=STATUS_NO_SIGNED)
        events = [event, event]

        response = await self.audit_general.log_bulk(events=events, verbose=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        for result in response.result.results:
            self.assertIsNotNone(result.envelope)
            self.assertIsNotNone(result.envelope.event)
            self.assertEqual(result.envelope.event["message"], MSG_NO_SIGNED)
            self.assertIsNone(result.consistency_proof)
            self.assertEqual(result.consistency_verification, EventVerification.NONE)
            self.assertEqual(result.membership_verification, EventVerification.NONE)
            self.assertEqual(result.signature_verification, EventVerification.NONE)

    async def test_log_bulk_and_sign(self):
        event = Event(message=MSG_SIGNED_LOCAL, actor=ACTOR, status=STATUS_SIGNED)
        events = [event, event]

        response = await self.audit_local_sign.log_bulk(events=events, verbose=True, sign_local=True)
        self.assertEqual(response.status, ResponseStatus.SUCCESS)
        self.assertEqual(len(response.result.results), 2)
        for result in response.result.results:
            self.assertIsNotNone(result.envelope)
            self.assertIsNotNone(result.envelope.event)
            self.assertEqual(result.envelope.event["message"], MSG_SIGNED_LOCAL)
            self.assertIsNone(result.consistency_proof)
            self.assertEqual(result.consistency_verification, EventVerification.NONE)
            self.assertEqual(result.membership_verification, EventVerification.NONE)
            self.assertEqual(result.signature_verification, EventVerification.PASS)
            self.assertEqual(
                result.envelope.public_key,
                r'{"algorithm":"ED25519","key":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAlvOyDMpK2DQ16NI8G41yINl01wMHzINBahtDPoh4+mE=\n-----END PUBLIC KEY-----\n"}',
            )

    async def test_log_bulk_async(self):
        event = Event(message=MSG_NO_SIGNED, actor=ACTOR, status=STATUS_NO_SIGNED)
        events = [event, event]

        response = await self.audit_general.log_bulk_async(events=events, verbose=True)
        self.assertEqual(202, response.http_status)
        self.assertIsNone(response.result)

    async def test_download(self):
        limit = 2
        max_result = 3
        response_search = await self.audit_general.search(
            query="message:" + MSG_SIGNED_LOCAL,
            order=SearchOrder.ASC,
            limit=limit,
            max_results=max_result,
            verbose=True,
            start="21d",
        )
        self.assertEqual(response_search.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response_search.result.id)
        self.assertEqual(len(response_search.result.events), limit)
        self.assertEqual(response_search.result.count, max_result)

        response_download = await self.audit_general.download_results(
            result_id=response_search.result.id, format=DownloadFormat.JSON
        )
        self.assertEqual(response_download.status, ResponseStatus.SUCCESS)
        self.assertIsNotNone(response_download.result.dest_url)

        file = await self.audit_general.download_file(url=response_download.result.dest_url)
        file.save("./")

    async def test_export_download(self) -> None:
        export_res = await self.audit_general.export(
            start=datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(days=1),
            end=datetime.datetime.now(tz=datetime.timezone.utc),
            verbose=False,
        )
        self.assertEqual(export_res.status, "Accepted")

        max_retries = 10
        for retry in range(max_retries):
            try:
                response = await self.audit_general.poll_result(request_id=export_res.request_id)
                if response.status == "Success":
                    break
            except pe.AcceptedRequestException:
                pass
            except pe.NotFound:
                pass

            if retry == max_retries - 1:
                self.log.warning("The result of request '%s' took too long to be ready.", export_res.request_id)
                return

            await sleep(3)

        download_res = await self.audit_general.download_results(request_id=export_res.request_id)
        self.assertEqual(download_res.status, "Success")
        self.assertIsNotNone(download_res.result.dest_url)

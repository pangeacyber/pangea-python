from secrets import token_hex
from unittest import TestCase

from pangea import PangeaConfig
from pangea.asyncio.services.authz import AuthZAsync
from pangea.services import AuthZ
from pangea.services.authz import Resource, Subject, Tuple, TupleListFilter
from pangea.tools import TestEnvironment, get_test_token, get_test_url_template, logger_set_pangea_config
from tests.test_tools import load_test_environment

TEST_ENVIRONMENT = load_test_environment(AuthZ.service_name, TestEnvironment.LIVE)

rand_str = token_hex(8)
folder1 = f"folder_1_{rand_str}"
folder2 = f"folder_2_{rand_str}"
user1 = f"user_1_{rand_str}"
user2 = f"user_2_{rand_str}"

type_folder = "folder"
type_user = "user"
relation_owner = "owner"
relation_editor = "editor"
relation_reader = "reader"


class TestAuthZIntegration(TestCase):
    def setUp(self) -> None:
        self.token = get_test_token(TEST_ENVIRONMENT)
        self.url_template = get_test_url_template(TEST_ENVIRONMENT)
        config = PangeaConfig(base_url_template=self.url_template, custom_user_agent="sdk-test")
        self.authz = AuthZAsync(self.token, config=config, logger_name="pangea")
        logger_set_pangea_config(logger_name=self.authz.logger.name)

    async def test_integration(self) -> None:
        # Create tuples
        r_create = await self.authz.tuple_create(
            [
                Tuple(
                    resource=Resource(type=type_folder, id=folder1),
                    relation=relation_reader,
                    subject=Subject(type=type_user, id=user1),
                ),
                Tuple(
                    resource=Resource(type=type_folder, id=folder1),
                    relation=relation_editor,
                    subject=Subject(type=type_user, id=user2),
                ),
                Tuple(
                    resource=Resource(type=type_folder, id=folder2),
                    relation=relation_editor,
                    subject=Subject(type=type_user, id=user1),
                ),
                Tuple(
                    resource=Resource(type=type_folder, id=folder2),
                    relation=relation_owner,
                    subject=Subject(type=type_user, id=user2),
                ),
            ]
        )

        self.assertIsNone(r_create.result)

        # Tuple list with resource
        r_list_with_resource = await self.authz.tuple_list(
            filter=TupleListFilter(resource_type=type_folder, resource_id=folder1)
        )

        self.assertIsNotNone(r_list_with_resource.result)
        assert r_list_with_resource.result
        self.assertEqual(len(r_list_with_resource.result.tuples), 2)

        # Tuple list with subject
        r_list_with_subject = await self.authz.tuple_list(
            filter=TupleListFilter(subject_type=type_user, subject_id=user1)
        )

        self.assertIsNotNone(r_list_with_subject.result)
        assert r_list_with_subject.result
        self.assertEqual(len(r_list_with_subject.result.tuples), 2)

        # Tuple delete
        r_delete = await self.authz.tuple_delete(
            tuples=[
                Tuple(
                    resource=Resource(type=type_folder, id=folder1),
                    relation=relation_reader,
                    subject=Subject(type=type_user, id=user1),
                )
            ]
        )

        self.assertIsNone(r_delete.result)

        # Check no debug
        r_check = await self.authz.check(
            resource=Resource(type=type_folder, id=folder1),
            action="reader",
            subject=Subject(type=type_user, id=user2),
        )

        self.assertIsNotNone(r_check.result)
        assert r_check.result
        self.assertFalse(r_check.result.allowed)
        self.assertIsNone(r_check.result.debug)
        self.assertIsNotNone(r_check.result.schema_id)
        self.assertIsNotNone(r_check.result.schema_version)

        # Check debug
        r_check = await self.authz.check(
            resource=Resource(type=type_folder, id=folder1),
            action="editor",
            subject=Subject(type=type_user, id=user2),
            debug=True,
        )

        self.assertIsNotNone(r_check.result)
        assert r_check.result
        self.assertTrue(r_check.result.allowed)
        self.assertIsNotNone(r_check.result.debug)
        self.assertIsNotNone(r_check.result.schema_id)
        self.assertIsNotNone(r_check.result.schema_version)

        r_check = await self.authz.check(
            resource=Resource(type=type_folder, id=folder1),
            action="editor",
            subject=Subject(type=type_user, id=user2),
            debug=True,
        )

        self.assertIsNotNone(r_check.result)
        assert r_check.result
        self.assertTrue(r_check.result.allowed)
        self.assertIsNotNone(r_check.result.debug)
        self.assertIsNotNone(r_check.result.schema_id)
        self.assertIsNotNone(r_check.result.schema_version)

        # List resources
        r_list_resources = await self.authz.list_resources(
            type=type_folder, action=relation_editor, subject=Subject(type=type_user, id=user2)
        )

        self.assertIsNotNone(r_list_resources.result)
        assert r_list_resources.result
        self.assertEqual(len(r_list_resources.result.ids), 1)

        # List subjects
        r_list_subjects = await self.authz.list_subjects(
            resource=Resource(type=type_folder, id=folder2), action=relation_editor
        )

        self.assertIsNotNone(r_list_subjects.result)
        assert r_list_subjects.result
        self.assertEqual(len(r_list_subjects.result.subjects), 1)

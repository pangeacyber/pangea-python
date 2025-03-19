import datetime
import unittest

import pangea.services.authz as m
from pangea import PangeaConfig
from pangea.services import AuthZ
from pangea.tools import TestEnvironment, get_test_token, get_test_url_template, logger_set_pangea_config
from tests.test_tools import load_test_environment

TEST_ENVIRONMENT = load_test_environment(AuthZ.service_name, TestEnvironment.LIVE)

time_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
folder1 = "folder_1_" + time_str
folder2 = "folder_2_" + time_str
user1 = "user_1_" + time_str
user2 = "user_2_" + time_str

type_folder = "folder"
type_user = "user"
relation_owner = "owner"
relation_editor = "editor"
relation_reader = "reader"


class TestAuthZIntegration(unittest.TestCase):
    def setUp(self) -> None:
        self.token = get_test_token(TEST_ENVIRONMENT)
        self.url_template = get_test_url_template(TEST_ENVIRONMENT)
        config = PangeaConfig(base_url_template=self.url_template, custom_user_agent="sdk-test")
        self.authz = AuthZ(self.token, config=config, logger_name="pangea")
        logger_set_pangea_config(logger_name=self.authz.logger.name)

    def test_integration(self) -> None:
        # Create tuples
        r_create = self.authz.tuple_create(
            [
                m.Tuple(
                    resource=m.Resource(type=type_folder, id=folder1),
                    relation=relation_reader,
                    subject=m.Subject(type=type_user, id=user1),
                ),
                m.Tuple(
                    resource=m.Resource(type=type_folder, id=folder1),
                    relation=relation_editor,
                    subject=m.Subject(type=type_user, id=user2),
                ),
                m.Tuple(
                    resource=m.Resource(type=type_folder, id=folder2),
                    relation=relation_editor,
                    subject=m.Subject(type=type_user, id=user1),
                ),
                m.Tuple(
                    resource=m.Resource(type=type_folder, id=folder2),
                    relation=relation_owner,
                    subject=m.Subject(type=type_user, id=user2),
                ),
            ]
        )

        self.assertIsNone(r_create.result)

        # Tuple list with resource
        r_list_with_resource = self.authz.tuple_list(
            filter=m.TupleListFilter(resource_type=type_folder, resource_id=folder1)
        )

        self.assertIsNotNone(r_list_with_resource.result)
        assert r_list_with_resource.result
        self.assertEqual(len(r_list_with_resource.result.tuples), 2)

        # Tuple list with subject
        r_list_with_subject = self.authz.tuple_list(filter=m.TupleListFilter(subject_type=type_user, subject_id=user1))

        self.assertIsNotNone(r_list_with_subject.result)
        assert r_list_with_subject.result
        self.assertEqual(len(r_list_with_subject.result.tuples), 2)

        # Tuple delete
        r_delete = self.authz.tuple_delete(
            tuples=[
                m.Tuple(
                    resource=m.Resource(type=type_folder, id=folder1),
                    relation=relation_reader,
                    subject=m.Subject(type=type_user, id=user1),
                )
            ]
        )

        self.assertIsNone(r_delete.result)

        # Check no debug
        r_check = self.authz.check(
            resource=m.Resource(type=type_folder, id=folder1),
            action="reader",
            subject=m.Subject(type=type_user, id=user2),
        )

        self.assertIsNotNone(r_check.result)
        assert r_check.result
        self.assertFalse(r_check.result.allowed)
        self.assertIsNone(r_check.result.debug)
        self.assertIsNotNone(r_check.result.schema_id)
        self.assertIsNotNone(r_check.result.schema_version)

        # Check debug
        r_check = self.authz.check(
            resource=m.Resource(type=type_folder, id=folder1),
            action="editor",
            subject=m.Subject(type=type_user, id=user2),
            debug=True,
        )

        self.assertIsNotNone(r_check.result)
        assert r_check.result
        self.assertTrue(r_check.result.allowed)
        self.assertIsNotNone(r_check.result.debug)
        self.assertIsNotNone(r_check.result.schema_id)
        self.assertIsNotNone(r_check.result.schema_version)

        r_check = self.authz.check(
            resource=m.Resource(type=type_folder, id=folder1),
            action="editor",
            subject=m.Subject(type=type_user, id=user2),
            debug=True,
        )

        self.assertIsNotNone(r_check.result)
        assert r_check.result
        self.assertTrue(r_check.result.allowed)
        self.assertIsNotNone(r_check.result.debug)
        self.assertIsNotNone(r_check.result.schema_id)
        self.assertIsNotNone(r_check.result.schema_version)

        # List resources
        r_list_resources = self.authz.list_resources(
            type=type_folder, action=relation_editor, subject=m.Subject(type=type_user, id=user2)
        )

        self.assertIsNotNone(r_list_resources.result)
        assert r_list_resources.result
        self.assertEqual(len(r_list_resources.result.ids), 1)

        # List subjects
        r_list_subjects = self.authz.list_subjects(
            resource=m.Resource(type=type_folder, id=folder2), action=relation_editor
        )

        self.assertIsNotNone(r_list_subjects.result)
        assert r_list_subjects.result
        self.assertEqual(len(r_list_subjects.result.subjects), 1)

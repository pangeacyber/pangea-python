import datetime
import unittest

from pangea.deep_verify import deep_verify
from pangea.dump_audit import dump_audit
from pangea.tools import TestEnvironment, get_test_domain, get_test_token, init_audit

TEST_ENVIRONMENT = TestEnvironment.LIVE


class TestAuditTools(unittest.TestCase):
    def setUp(self):
        self.token = get_test_token(TEST_ENVIRONMENT)
        self.domain = get_test_domain(TEST_ENVIRONMENT)
        self.start_date = "2023-05-02"
        self.end_date = "2023-05-05"
        self.dump_filename = "./tests/testdata/dump.json"
        self.artifact_filename = "./tests/testdata/log_artifact.json"

    def test_dump_audit(self):
        with open(self.dump_filename, "a") as file:
            try:
                audit = init_audit(self.token, self.domain)
                cnt = dump_audit(
                    audit,
                    file,
                    datetime.datetime.fromisoformat(self.start_date),
                    datetime.datetime.fromisoformat(self.end_date),
                )
                print(f"\nFile {self.dump_filename} created with {cnt} events.")

            except Exception as e:
                print(f"error: {str(e)}")
                self.assertTrue(False)

    def test_verify_audit(self):
        with open(self.dump_filename, "r") as file:
            try:
                audit = init_audit(self.token, self.domain)
                errors = deep_verify(audit, file)

                print("\n\nTotal errors:")
                for key, val in errors.items():
                    print(f"\t{key.title()}: {val}")
                print()

            except Exception as e:
                import traceback

                print(traceback.format_exc())
                print(e)
                self.assertTrue(False)

    def test_deep_verify(self):
        with open(self.dump_filename, "r") as file:
            try:
                audit = init_audit(self.token, self.domain)
                errors = deep_verify(audit, file)

                print("\n\nTotal errors:")
                for key, val in errors.items():
                    print(f"\t{key.title()}: {val}")
                print()

            except Exception as e:
                import traceback

                print(traceback.format_exc())
                print(e)
                self.assertTrue(False)

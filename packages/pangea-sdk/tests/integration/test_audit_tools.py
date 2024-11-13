from __future__ import annotations

import datetime
import unittest
from pathlib import Path

from pangea.deep_verify import deep_verify
from pangea.dump_audit import dump_audit
from pangea.services import Audit
from pangea.tools import TestEnvironment, get_test_domain, get_test_token, init_audit
from tests.test_tools import load_test_environment

TEST_ENVIRONMENT = load_test_environment(Audit.service_name, TestEnvironment.LIVE)


class TestAuditTools(unittest.TestCase):
    def setUp(self) -> None:
        self.token = get_test_token(TEST_ENVIRONMENT)
        self.domain = get_test_domain(TEST_ENVIRONMENT)
        self.start_date = "2023-05-02"
        self.end_date = "2023-05-05"
        self.dump_filename = "./tests/testdata/dump.json"
        self.artifact_filename = "./tests/testdata/log_artifact.json"

    def test_01_dump_audit(self) -> None:
        audit = init_audit(self.token, self.domain)
        with Path(self.dump_filename).open("a") as file:
            cnt = dump_audit(
                audit,
                file,
                datetime.datetime.fromisoformat(self.start_date),
                datetime.datetime.fromisoformat(self.end_date),
            )
            print(f"\nFile {self.dump_filename} created with {cnt} events.")

    def test_02_deep_verify(self) -> None:
        audit = init_audit(self.token, self.domain)
        with Path(self.dump_filename).open() as file:
            errors = deep_verify(audit, file)
            print("\n\nWarnings:")
            val1 = errors["not_persisted"]
            print(f"\tnot_persisted: {val1}")

            print("\nTotal errors:")
            for key, val in errors.items():
                if key == "not_persisted":
                    continue
                print(f"\t{key.title()}: {val}")
            print()

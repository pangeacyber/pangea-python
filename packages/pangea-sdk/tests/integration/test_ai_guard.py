from __future__ import annotations

import unittest

from pangea import PangeaConfig
from pangea.services import AIGuard
from pangea.tools import TestEnvironment, get_test_domain, get_test_token, logger_set_pangea_config
from tests.test_tools import load_test_environment

TEST_ENVIRONMENT = load_test_environment(AIGuard.service_name, TestEnvironment.LIVE)


class TestAIGuard(unittest.TestCase):
    def setUp(self) -> None:
        token = get_test_token(TEST_ENVIRONMENT)
        domain = get_test_domain(TEST_ENVIRONMENT)
        config = PangeaConfig(domain=domain, custom_user_agent="sdk-test")
        self.client = AIGuard(token, config=config)
        logger_set_pangea_config(logger_name=self.client.logger.name)

    def test_text_guard(self) -> None:
        response = self.client.guard_text("hello world")
        assert response.status == "Success"
        assert response.result
        assert response.result.redacted_prompt
        assert response.result.findings.artifact_count is None
        assert response.result.findings.malicious_count is None

        response = self.client.guard_text("security@pangea.cloud")
        assert response.status == "Success"
        assert response.result
        assert response.result.redacted_prompt
        assert response.result.findings.artifact_count == 1
        assert response.result.findings.malicious_count is None
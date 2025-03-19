from __future__ import annotations

import unittest

from pangea import PangeaConfig
from pangea.asyncio.services import AIGuardAsync
from pangea.tools import TestEnvironment, get_test_token, get_test_url_template, logger_set_pangea_config
from tests.test_tools import load_test_environment

TEST_ENVIRONMENT = load_test_environment(AIGuardAsync.service_name, TestEnvironment.LIVE)


class TestAIGuardAsync(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        token = get_test_token(TEST_ENVIRONMENT)
        url_template = get_test_url_template(TEST_ENVIRONMENT)
        config = PangeaConfig(base_url_template=url_template, custom_user_agent="sdk-test")
        self.client = AIGuardAsync(token, config=config)
        logger_set_pangea_config(logger_name=self.client.logger.name)

    async def asyncTearDown(self) -> None:
        await self.client.close()

    async def test_text_guard(self) -> None:
        response = await self.client.guard_text("what was pangea?", debug=True)
        assert response.status == "Success"
        assert response.result
        assert response.result.prompt_text

        if response.result.detectors.prompt_injection:
            assert response.result.detectors.prompt_injection.detected is False
            assert response.result.detectors.prompt_injection.data is None

        if response.result.detectors.pii_entity:
            assert response.result.detectors.pii_entity.detected is False
            assert response.result.detectors.pii_entity.data is None

        if response.result.detectors.malicious_entity:
            assert response.result.detectors.malicious_entity.detected is False
            assert response.result.detectors.malicious_entity.data is None

    async def test_text_guard_messages(self) -> None:
        response = await self.client.guard_text(messages=[{"role": "user", "content": "hello world"}])
        assert response.status == "Success"
        assert response.result
        assert response.result.prompt_messages

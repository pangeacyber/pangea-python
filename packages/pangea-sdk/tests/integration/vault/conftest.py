import os
import random
from base64 import b64encode

import pytest
from pangea import PangeaConfig
from pangea.services.vault.vault import Vault
from pangea.tools import TestEnvironment, get_test_domain, get_test_token

TEST_ENVIRONMENT = TestEnvironment.DEVELOP


@pytest.fixture(scope="session")
def config():
    domain = get_test_domain(TEST_ENVIRONMENT)
    return PangeaConfig(domain=domain)


@pytest.fixture(scope="session")
def vault(config):
    token = get_test_token(TEST_ENVIRONMENT)
    return Vault(token, config=config)


@pytest.fixture(scope="session")
def plain_text() -> str:
    msg = "hello"
    return b64encode(msg.encode("ascii")).decode("ascii")


@pytest.fixture(scope="session")
def test_name():
    return f"test_{random.randint(0, 1000)}"

import pytest
import os
from base64 import b64encode
import random

from pangea.services.vault.vault import Vault
from pangea import PangeaConfig


@pytest.fixture(scope="session")
def config():
    domain = os.getenv("PANGEA_BRANCH_DOMAIN")
    return PangeaConfig(domain=domain, environment="local")


@pytest.fixture(scope="session")
def vault(config):
    token = os.getenv("PANGEA_INTEGRATION_VAULT_TOKEN")
    return Vault(token, config=config)


@pytest.fixture(scope="session")
def plain_text() -> str:
    msg = "hello"
    return b64encode(msg.encode("ascii")).decode("ascii")


@pytest.fixture(scope="session")
def test_name():
    return f"test_{random.randint(0, 1000)}"

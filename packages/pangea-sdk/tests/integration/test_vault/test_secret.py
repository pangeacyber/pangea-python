from datetime import datetime, timedelta
import time
import pytest

from pangea.services.vault.models.secret import CreateSecretResult
import pangea.exceptions as pexc

from util import create_or_store_params, update_params


@pytest.fixture(scope="session")
def secret_ok(vault) -> CreateSecretResult:
    response = vault.store_secret(secret="very very secret")
    yield response.result
    vault.delete(response.result.id)


@pytest.fixture(scope="session")
def secret_expired(vault, secret_ok: CreateSecretResult) -> CreateSecretResult:
    now = datetime.now()
    response = vault.store_secret(
        secret=secret_ok.secret,
        expiration=(now + timedelta(seconds=1)),
    )
    time.sleep(1)
    yield response.result
    vault.delete(response.result.id)


@pytest.fixture(scope="session")
def secret_revoked(vault, secret_ok: CreateSecretResult) -> CreateSecretResult:
    response = vault.store_secret(
        secret=secret_ok.secret,
    )
    vault.revoke(response.result.id)
    yield response.result
    vault.delete(response.result.id)


@pytest.fixture(scope="session")
def secrets(secret_ok, secret_revoked, secret_expired):
    return {
        "ok": secret_ok.id,
        "revoked": secret_revoked.id,
        "expired": secret_expired.id,
        "missing": "xxx",
    }


@pytest.mark.parametrize(("param_name", "param_value", "param_response"), create_or_store_params)
def test_store_secret(vault, secret_ok, param_name, param_value, param_response):
    req = {
        "name": "tes",
        "folder": "/tmp",
        "metadata": {},
        "tags": [],
        "auto_rotate": False,
        "rotation_policy": None,
        "expiration": None,
        "secret": secret_ok.secret,
    }
    req[param_name] = param_value

    response = vault.store_secret(**req)
    secret_id = response.result.id

    try:
        response = vault.retrieve(secret_id, verbose=True)
        assert getattr(response.result, param_name) == param_response
    finally:
        vault.delete(secret_id)


@pytest.mark.parametrize(("param_name", "param_value", "param_response"), update_params)
def test_update_attributes_secret(vault, secret_ok, param_name, param_value, param_response):
    req = {
        "id": secret_ok.id,
        param_name: param_value
    }

    response = vault.update(**req)
    key_id = response.result.id

    response = vault.retrieve(key_id, verbose=True)
    assert getattr(response.result, param_name) == param_response


@pytest.mark.parametrize(("key_name", "ok"), [
    ("ok", True),
    ("expired", False),
    ("revoked", False),
])
def test_update_keys_secret(vault, secrets, key_name, ok):
    if ok:
        vault.update(id=secrets[key_name], name="pepe")
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.update(id=secrets[key_name], name="pepe")            


@pytest.mark.parametrize(("key_name", "ok"), [
    ("ok", True),
    ("missing", False),
    ("expired", False),
    ("revoked", False),
])
def test_rotate_keys_secret(vault, secrets, key_name, ok):
    if ok:
        vault.rotate_secret(secrets[key_name], "secreto")
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.rotate_secret(secrets[key_name], "secreto")


def test_rotate_params_secret(vault, secret_ok):
    prev_version = vault.retrieve(id=secret_ok.id).result.version
    vault.rotate_secret(secret_ok.id, "old secret")
    curr_version = vault.retrieve(id=secret_ok.id).result.version
    assert curr_version == prev_version + 1


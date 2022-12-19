from datetime import datetime, timedelta
import time
import pytest

from pangea.services.vault.models.symmetric import CreateKeyResult
from pangea.services.vault.models.common import KeyAlgorithm
import pangea.exceptions as pexc

from util import create_or_store_key_params, update_params


@pytest.fixture(scope="session")
def symmetric_key_ok(vault) -> CreateKeyResult:
    response = vault.create_symmetric(managed=False)
    yield response.result
    vault.delete(response.result.id)


@pytest.fixture(scope="session")
def symmetric_key_expired(vault, symmetric_key_ok: CreateKeyResult) -> CreateKeyResult:
    now = datetime.now()
    response = vault.store_symmetric(
        algorithm=symmetric_key_ok.algorithm,
        managed=False,
        key=symmetric_key_ok.key,
        expiration=(now + timedelta(seconds=1)),
    )
    time.sleep(1)
    yield response.result
    vault.delete(response.result.id)


@pytest.fixture(scope="session")
def symmetric_key_revoked(vault, symmetric_key_ok: CreateKeyResult) -> CreateKeyResult:
    response = vault.store_symmetric(
        algorithm=symmetric_key_ok.algorithm,
        managed=False,
        key=symmetric_key_ok.key,
    )
    vault.revoke(response.result.id)
    yield response.result
    vault.delete(response.result.id)


@pytest.fixture
def cipher_text(vault, plain_text, symmetric_key_ok) -> str:
    return vault.encrypt(symmetric_key_ok.id, plain_text).result.cipher_text


@pytest.fixture(scope="session")
def symmetric_keys(symmetric_key_ok, symmetric_key_revoked, symmetric_key_expired) -> dict[str, str]:
    return {
        "ok": symmetric_key_ok.id,
        "revoked": symmetric_key_revoked.id,
        "expired": symmetric_key_expired.id,
        "missing": "xxx",
    }


@pytest.mark.parametrize(("param_name", "param_value", "param_response"), create_or_store_key_params)
def test_create_symmetric(vault, param_name, param_value, param_response):
    req = {
        "algorithm": KeyAlgorithm.AES, 
        "name": "tes",
        "folder": "/tmp",
        "metadata": {},
        "tags": [],
        "auto_rotate": False,
        "rotation_policy": None,
        "retain_previous_version": True,
        "store": True,
        "expiration": None,
        "managed": False,
    }
    req[param_name] = param_value

    response = vault.create_symmetric(**req)
    key_id = response.result.id

    response = vault.retrieve(key_id, verbose=True)
    assert getattr(response.result, param_name) == param_response

    vault.delete(key_id)


@pytest.mark.parametrize(("param_name", "param_value", "param_response"), create_or_store_key_params)
def test_store_symmetric(vault, symmetric_key_ok, param_name, param_value, param_response):
    req = {
        "algorithm": KeyAlgorithm.AES,
        "name": "tes",
        "folder": "/tmp",
        "metadata": {},
        "tags": [],
        "auto_rotate": False,
        "rotation_policy": None,
        "expiration": None,
        "managed": False,
        "key": symmetric_key_ok.key,
    }
    req[param_name] = param_value

    response = vault.store_symmetric(**req)
    key_id = response.result.id

    try:
        response = vault.retrieve(key_id, verbose=True)
        assert getattr(response.result, param_name) == param_response
    finally:
        vault.delete(key_id)


@pytest.mark.parametrize(("key_name", "ok"), [
    ("expired", False),
    ("revoked", False),
    ("ok", True),
])
def test_encrypt(vault, symmetric_keys, plain_text, key_name, ok):
    if ok:
        vault.encrypt(symmetric_keys[key_name], plain_text)
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.encrypt(symmetric_keys[key_name], plain_text)


@pytest.mark.parametrize(("key_name"), [
    "expired",
    "revoked",
    "ok",
])
def test_decrypt(vault, symmetric_keys, plain_text, cipher_text, key_name):
    response = vault.decrypt(symmetric_keys[key_name], cipher_text)
    assert response.result.plain_text == plain_text


@pytest.mark.parametrize(("param_name", "param_value", "param_response"), update_params)
def test_update_attributes_symmetric(vault, symmetric_key_ok, param_name, param_value, param_response):
    req = {
        "id": symmetric_key_ok.id,
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
def test_update_keys_symmetric(vault, symmetric_keys, key_name, ok):
    if ok:
        vault.update(id=symmetric_keys[key_name], name="pepe")
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.update(id=symmetric_keys[key_name], name="pepe")            


@pytest.mark.parametrize(("key_name", "ok"), [
    ("ok", True),
    ("missing", False),
    ("expired", False),
    ("revoked", False),
])
def test_rotate_keys_symmetric(vault, symmetric_keys, key_name, ok):
    if ok:
        vault.rotate_symmetric(symmetric_keys[key_name])
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.rotate_symmetric(symmetric_keys[key_name])


@pytest.mark.parametrize(("name", "params", "ok"), [
    ("ok", {"key": "symmetric_key_ok.key"}, True),
    ("missing", {"key": "None"}, True),
    ("wrong", {"key": "'xxx'"}, False),
])
def test_rotate_params_symmetric(vault, symmetric_key_ok, name, params, ok):
    args = {
        "id": symmetric_key_ok.id,
        "key": eval(params["key"]),
    }

    if ok:
        prev_version = vault.retrieve(id=symmetric_key_ok.id).result.version
        vault.rotate_symmetric(**args)
        curr_version = vault.retrieve(id=symmetric_key_ok.id).result.version
        assert curr_version == prev_version + 1

    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.rotate_symmetric(**args)

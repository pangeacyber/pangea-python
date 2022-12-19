from datetime import datetime, timedelta
import time
import pytest
from base64 import b64encode

import pangea.exceptions as pexc
from pangea.services.vault.models.asymmetric import CreateKeyPairResult, KeyPairAlgorithm


from util import create_or_store_key_params, update_params


@pytest.fixture(scope="session")
def asymmetric_key_ok(vault) -> CreateKeyPairResult:
    response = vault.create_asymmetric(managed=False)
    yield response.result
    try:
        vault.delete(response.result.id)
    except:
        pass


@pytest.fixture(scope="session")
def asymmetric_key_expired(vault, asymmetric_key_ok: CreateKeyPairResult) -> CreateKeyPairResult:
    now = datetime.now()
    response = vault.store_asymmetric(
        algorithm=asymmetric_key_ok.algorithm,
        managed=False,
        public_key=asymmetric_key_ok.public_key,
        private_key=asymmetric_key_ok.private_key,
        expiration=(now + timedelta(seconds=1)))
    time.sleep(1)
    yield response.result
    try:
        vault.delete(response.result.id)
    except:
        pass


@pytest.fixture(scope="session")
def asymmetric_key_revoked(vault, asymmetric_key_ok: CreateKeyPairResult) -> CreateKeyPairResult:
    response = vault.store_asymmetric(
        algorithm=asymmetric_key_ok.algorithm,
        managed=False,
        public_key=asymmetric_key_ok.public_key,
        private_key=asymmetric_key_ok.private_key)
    vault.revoke(response.result.id)
    yield response.result
    try:
        vault.delete(response.result.id)
    except:
        pass


@pytest.fixture(scope="session")
def asymmetric_keys(asymmetric_key_ok, asymmetric_key_revoked, asymmetric_key_expired):
    return {
        "ok": asymmetric_key_ok.id,
        "revoked": asymmetric_key_revoked.id,
        "expired": asymmetric_key_expired.id,
        "missing": "xxx",
    }


@pytest.fixture(scope="session")
def signature(vault, plain_text, asymmetric_key_ok) -> str:
    return vault.sign(asymmetric_key_ok.id, plain_text).result.signature


@pytest.mark.parametrize(("param_name", "param_value", "param_response"), create_or_store_key_params)
def test_create_asymmetric(vault, param_name, param_value, param_response):
    req = {
        "algorithm": KeyPairAlgorithm.Ed25519, 
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

    response = vault.create_asymmetric(**req)
    key_id = response.result.id

    try:
        response = vault.retrieve(key_id, verbose=True)
        assert getattr(response.result, param_name) == param_response
    finally:
        vault.delete(key_id)


@pytest.mark.parametrize(("param_name", "param_value", "param_response"), create_or_store_key_params)
def test_store_asymmetric(vault, asymmetric_key_ok, param_name, param_value, param_response):
    req = {
        "algorithm": KeyPairAlgorithm.Ed25519, 
        "name": "tes",
        "folder": "/tmp",
        "metadata": {},
        "tags": [],
        "auto_rotate": False,
        "rotation_policy": None,
        "expiration": None,
        "managed": False,
        "public_key": asymmetric_key_ok.public_key,
        "private_key": asymmetric_key_ok.private_key,
    }
    req[param_name] = param_value

    response = vault.store_asymmetric(**req)
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
def test_sign_keys(vault, asymmetric_keys, plain_text, key_name, ok):
    if ok:
        vault.sign(asymmetric_keys[key_name], plain_text)
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.sign(asymmetric_keys[key_name], plain_text)


@pytest.mark.parametrize(("name", "plain_text", "ok"), [
    ("ok", b64encode(b"hello").decode(), True),
    ("not base64", "hello", False),
])
def test_sign_params(vault, asymmetric_key_ok, name, plain_text, ok):
    if ok:
        vault.sign(asymmetric_key_ok.id, plain_text)
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.sign(asymmetric_key_ok.id, plain_text)


@pytest.mark.parametrize(("key_name"), [
    "expired",
    "revoked",
    "ok",
])
def test_verify(vault, asymmetric_keys, plain_text, signature, key_name):
    resp = vault.verify(asymmetric_keys[key_name], plain_text, signature)
    assert resp.result.valid_signature


@pytest.mark.skip("encrypting with asymmetric not working yet")
@pytest.mark.parametrize(("key_name", "ok"), [
    ("expired", False),
    ("revoked", False),
    ("ok", True),
])
def test_encrypt(vault, asymmetric_keys, plain_text, key_name, ok):
    if ok:
        vault.encrypt(asymmetric_keys[key_name], plain_text)
    else:
        with pytest.raises(pexc.VaultAPIException):
            vault.encrypt(asymmetric_keys[key_name], plain_text)


@pytest.mark.skip("encrypting with asymmetric not working yet")
@pytest.mark.parametrize(("key_name"), [
    "expired",
    "revoked",
    "ok",
])
def test_decrypt(vault, asymmetric_keys, plain_text, cipher_text, key_name):
    response = vault.decrypt(asymmetric_keys[key_name], cipher_text)
    assert response.result.plain_text == plain_text


@pytest.mark.parametrize(("param_name", "param_value", "param_response"), update_params)
def test_update_attributes_asymmetric(vault, asymmetric_key_ok, param_name, param_value, param_response):
    req = {
        "id": asymmetric_key_ok.id,
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
def test_update_keys_asymmetric(vault, asymmetric_keys, key_name, ok):
    if ok:
        vault.update(id=asymmetric_keys[key_name], name="pepe")
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.update(id=asymmetric_keys[key_name], name="pepe")            


@pytest.mark.parametrize(("key_name", "ok"), [
    ("ok", True),
    ("missing", False),
    ("expired", False),
    ("revoked", False),
])
def test_rotate_keys_asymmetric(vault, asymmetric_keys, key_name, ok):
    if ok:
        vault.rotate_asymmetric(asymmetric_keys[key_name])
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.rotate_asymmetric(asymmetric_keys[key_name])


@pytest.mark.parametrize(("name", "params", "ok"), [
    ("both", {"public_key": "asymmetric_key_ok.public_key", "private_key": "asymmetric_key_ok.private_key"}, True),
    ("none", {"public_key": "None", "private_key": "None"}, True),
    ("one", {"public_key": "asymmetric_key_ok.public_key", "private_key": "None"}, False),
    ("other", {"public_key": "None", "private_key": "asymmetric_key_ok.private_key"}, False),
    ("wrong", {"public_key": "'xxx'", "private_key": "asymmetric_key_ok.private_key"}, False),
])
def test_rotate_params_asymmetric(vault, asymmetric_key_ok, name, params, ok):
    args = {
        "id": asymmetric_key_ok.id,
        "public_key": eval(params["public_key"]),
        "private_key": eval(params["private_key"])
    }

    if ok:
        prev_version = vault.retrieve(id=asymmetric_key_ok.id).result.version
        vault.rotate_asymmetric(**args)
        curr_version = vault.retrieve(id=asymmetric_key_ok.id).result.version
        assert curr_version == prev_version + 1

    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.rotate_asymmetric(**args)


@pytest.mark.parametrize(("key_name", "ok"), [
    ("expired", False),
    ("revoked", False),
    ("missing", False),
    ("ok", True)
])
def test_revoke(vault, asymmetric_keys, key_name, ok):
    if ok:
        vault.revoke(asymmetric_keys[key_name])
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.revoke(asymmetric_keys[key_name])


@pytest.mark.parametrize(("key_name", "ok"), [
    ("ok", True),
    ("missing", False)
])
def test_delete(vault, asymmetric_keys, key_name, ok):
    if ok:
        vault.delete(asymmetric_keys[key_name])

        with pytest.raises(pexc.PangeaAPIException):
            vault.retrieve(asymmetric_keys[key_name])

    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.delete(asymmetric_keys[key_name])

from datetime import datetime, timedelta
import time
import pytest
from base64 import b64encode

import pangea.exceptions as pexc
from pangea.services.vault.models.asymmetric import CreateKeyPairResult, KeyPairAlgorithm


from util import create_or_store_key_params, update_params


@pytest.fixture(scope="session")
def asymmetric_key_ok(test_name, vault) -> CreateKeyPairResult:
    response = vault.create_asymmetric(
        name=f"{test_name}_asymmetric_ok", 
        folder=test_name,
        managed=False)
    yield response.result
    try:
        vault.delete(response.result.id)
    except:
        pass


@pytest.fixture(scope="session")
def asymmetric_key_expired(vault, test_name, asymmetric_key_ok: CreateKeyPairResult) -> CreateKeyPairResult:
    now = datetime.now()
    response = vault.store_asymmetric(
        name=f"{test_name}_asymmetric_expired",
        folder=test_name,        
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
def asymmetric_key_revoked(vault, test_name, asymmetric_key_ok: CreateKeyPairResult) -> CreateKeyPairResult:
    response = vault.store_asymmetric(
        name=f"{test_name}_asymmetric_revoked",        
        folder=test_name,
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
        "name": "test",
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
    response = vault.create_asymmetric()
    if ok:
        vault.update(id=asymmetric_keys[key_name], tags=["pepe"])
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.update(id=asymmetric_keys[key_name], tags=["pepe"])            


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


# @pytest.mark.parametrize(("key_name", "ok"), [
#     ("expired", False),
#     ("revoked", False),
#     ("missing", False),
#     ("ok", True)
# ])
# def test_revoke(vault, asymmetric_keys, key_name, ok):
#     if ok:
#         vault.revoke(asymmetric_keys[key_name])
#     else:
#         with pytest.raises(pexc.PangeaAPIException):
#             vault.revoke(asymmetric_keys[key_name])


def test_delete(vault):
    key_ok = vault.create_asymmetric().result.id
    vault.delete(key_ok)
    with pytest.raises(pexc.PangeaAPIException):
        vault.retrieve(key_ok)

    key_missing = "xxx"
    with pytest.raises(pexc.PangeaAPIException):
        vault.delete(key_missing)


@pytest.mark.parametrize(("name", "filters", "num_results"), [
    ("name exact", {"name": "{test_name}_asymmetric_ok"}, 1),
    ("name not found", {"name": "xxx"}, 0),
    ("name contains", {"name__contains": "{test_name}_asymmetric"}, 3),
    ("folder", {"folder": "/{test_name}/"}, 3),
    # TODO: add more!
])
def test_list_filter(vault, test_name, asymmetric_keys, name, filters, num_results):
    filters_eval = {k: v.replace("{test_name}", test_name) for k, v in filters.items()}
    response = vault.list(filters_eval)
    assert response.result.count == num_results


# TODO: needs improvement
def test_list_pagination(vault, test_name, asymmetric_keys):
    response = vault.list({"folder": f"/{test_name}/"}, size=1)
    total = len(response.result.items)
    count = response.result.count

    while response.result.last is not None:
        response = vault.list({"folder": f"/{test_name}/"}, size=1, last=response.result.last)
        total += len(response.result.items)
    assert count == total


# TODO: needs improvement
def test_list_order(vault, test_name, asymmetric_keys):
    response = vault.list(filter={"folder": test_name}, order_by="name", size=10)
    for curr, next in zip(response.result.items, response.result.items[1:]):
        assert curr.name >= next.name


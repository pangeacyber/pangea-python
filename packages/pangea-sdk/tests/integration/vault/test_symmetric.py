import time
from base64 import b64encode
from datetime import datetime, timedelta

import pangea.exceptions as pexc
import pytest
from pangea.services.vault.models.common import KeyAlgorithm
from pangea.services.vault.vault import Vault

from .util import (
    create_or_store_key_params,
    update_params,
    vault_item_expired,
    vault_item_missing,
    vault_item_ok,
    vault_item_revoked,
)


@pytest.fixture(scope="session")
def canonical_symmetric_args():
    return {
        "algorithm": KeyAlgorithm.AES,
        "managed": False,
        "key": "oILlp2FUPHWiaqFXl4/1ww==",
    }


def _symmetric_key(vault: Vault, key_type, test_name, canonical_args, item_name):
    func = eval(f"vault_item_{item_name}")
    store_func = eval(f"vault.{key_type}_store")
    key_id = func(vault, store_func, f"{test_name}_{key_type}", canonical_args)
    return key_id


@pytest.fixture
def temp_symmetric_key(vault: Vault, test_name, canonical_symmetric_args, request):
    key_id = _symmetric_key(vault, "symmetric", test_name, canonical_symmetric_args, getattr(request, "param", "ok"))
    yield key_id
    try:
        vault.delete(key_id)
    except:
        pass


@pytest.fixture(scope="session")
def session_symmetric_key(vault: Vault, test_name, canonical_symmetric_args, request):
    name = getattr(request, "param", "ok")
    key_id = _symmetric_key(vault, "symmetric", f"{test_name}_session", canonical_symmetric_args, name)
    yield key_id
    try:
        vault.delete(key_id)
    except:
        pass


@pytest.fixture(scope="session")
def cipher_text(vault: Vault, canonical_symmetric_args, plain_text, test_name) -> str:
    return vault.encrypt(
        _symmetric_key(vault, "symmetric", test_name, canonical_symmetric_args, "ok"), plain_text
    ).result.cipher_text


@pytest.mark.parametrize(("param_name", "param_value", "param_response"), create_or_store_key_params)
def test_create_symmetric(vault: Vault, param_name, param_value, param_response):
    req = {
        "algorithm": KeyAlgorithm.AES,
        "name": "test",
        "folder": "/tmp",
        "metadata": {},
        "tags": [],
        "auto_rotate": False,
        "rotation_policy": None,
        # "retain_previous_version": True,
        "store": True,
        "expiration": None,
        "managed": False,
    }
    req[param_name] = param_value

    response = vault.symmetric_generate(**req)
    key_id = response.result.id

    try:
        response = vault.get(key_id, verbose=True)
        assert getattr(response.result, param_name) == param_response
    finally:
        vault.delete(key_id)


@pytest.mark.parametrize(("param_name", "param_value", "param_response"), create_or_store_key_params)
def test_store_symmetric(vault: Vault, canonical_symmetric_args, param_name, param_value, param_response):
    req = {
        "algorithm": KeyAlgorithm.AES,
        "name": "test",
        "folder": "/tmp",
        "metadata": {},
        "tags": [],
        "auto_rotate": False,
        "rotation_policy": None,
        # "retain_previous_version": True,
        "expiration": None,
        "managed": False,
    }
    req["key"] = canonical_symmetric_args["key"]
    req[param_name] = param_value

    response = vault.symmetric_store(**req)
    key_id = response.result.id

    try:
        response = vault.get(key_id, verbose=True)
        assert getattr(response.result, param_name) == param_response
    finally:
        vault.delete(key_id)


@pytest.mark.parametrize(
    ("session_symmetric_key", "ok"),
    [
        ("expired", False),
        ("revoked", False),
        ("ok", True),
    ],
    indirect=["session_symmetric_key"],
)
def test_encrypt(vault: Vault, session_symmetric_key, plain_text, ok):
    if ok:
        vault.encrypt(session_symmetric_key, plain_text)
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.encrypt(session_symmetric_key, plain_text)


@pytest.mark.parametrize(
    ("session_symmetric_key", "ok"),
    [
        ("expired", True),
        ("revoked", True),
        ("ok", True),
        ("missing", False),
    ],
    indirect=["session_symmetric_key"],
)
def test_decrypt(vault: Vault, session_symmetric_key, ok, plain_text, cipher_text):
    if ok:
        response = vault.decrypt(session_symmetric_key, cipher_text)
        assert response.result.plain_text == plain_text
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.decrypt(session_symmetric_key, cipher_text)


@pytest.mark.parametrize(("param_name", "param_value", "param_response"), update_params)
def test_update_attributes_symmetric(vault: Vault, temp_symmetric_key, param_name, param_value, param_response):
    req = {"id": temp_symmetric_key, param_name: param_value}

    response = vault.update(**req)
    key_id = response.result.id

    response = vault.get(key_id, verbose=True)
    assert getattr(response.result, param_name) == param_response


@pytest.mark.parametrize(
    ("temp_symmetric_key", "ok"),
    [
        ("ok", True),
        ("expired", False),
        ("revoked", False),
    ],
    indirect=["temp_symmetric_key"],
)
def test_update_keys_symmetric(vault: Vault, temp_symmetric_key, ok):
    if ok:
        vault.update(id=temp_symmetric_key, tags=["pepe"])
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.update(id=temp_symmetric_key, tags=["pepe"])


@pytest.mark.parametrize(
    ("temp_symmetric_key", "ok"),
    [
        ("ok", True),
        ("missing", False),
        ("expired", True),
        ("revoked", False),
    ],
    indirect=["temp_symmetric_key"],
)
def test_rotate_keys_symmetric(vault: Vault, temp_symmetric_key, ok):
    if ok:
        vault.symmetric_rotate(temp_symmetric_key)
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.symmetric_rotate(temp_symmetric_key)


@pytest.mark.parametrize(
    ("params", "ok"),
    [
        ({"key": "canonical_symmetric_args['key']"}, True),
        ({"key": "None"}, True),
        ({"key": "'xxx'"}, False),
    ],
    ids=[
        "both",
        "none",
        "wrong",
    ],
)
def test_rotate_params_symmetric(vault: Vault, temp_symmetric_key, canonical_symmetric_args, params, ok):
    args = {
        "id": temp_symmetric_key,
        "key": eval(params["key"]),
    }

    if ok:
        prev_version = vault.get(id=temp_symmetric_key).result.version
        vault.symmetric_rotate(**args)
        curr_version = vault.get(id=temp_symmetric_key).result.version
        assert curr_version == prev_version + 1

    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.symmetric_rotate(**args)


@pytest.mark.parametrize(
    ("temp_symmetric_key", "ok"),
    [("expired", False), ("revoked", False), ("missing", False), ("ok", True)],
    indirect=["temp_symmetric_key"],
)
def test_revoke(vault: Vault, temp_symmetric_key, ok):
    if ok:
        vault.revoke(temp_symmetric_key)
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.revoke(temp_symmetric_key)


@pytest.mark.parametrize(
    ("temp_symmetric_key", "ok"),
    [
        ("expired", True),
        ("revoked", True),
        ("ok", True),
        ("missing", False),
    ],
    indirect=["temp_symmetric_key"],
)
def test_delete(vault: Vault, temp_symmetric_key, ok):
    if ok:
        vault.delete(temp_symmetric_key)
        with pytest.raises(pexc.PangeaAPIException):
            vault.get(temp_symmetric_key)
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.delete(temp_symmetric_key)


@pytest.fixture(scope="session")
def list_symmetric_keys(vault: Vault, test_name, canonical_symmetric_args):
    keys = [
        _symmetric_key(vault, "symmetric", f"{test_name}_list", canonical_symmetric_args, name)
        for name in ["ok", "revoked", "expired"]
    ]

    yield keys
    for key in keys:
        try:
            vault.delete(key)
        except:
            pass


@pytest.mark.skip("list filter not working yet")
@pytest.mark.parametrize(
    ("filters", "num_results"),
    [
        ({"name": "{test_name}_list_symmetric_ok"}, 1),
        ({"name": "xxx"}, 0),
        ({"name__contains": "{test_name}_list_symmetric"}, 3),
        ({"folder": "/{test_name}_list_symmetric/"}, 3),
        # TODO: add more!
    ],
    ids=[
        "name exact",
        "name not found",
        "name contains",
        "folder",
    ],
)
def test_list_filter(vault: Vault, test_name, list_symmetric_keys, filters, num_results):
    filters_eval = {k: v.replace("{test_name}", test_name) for k, v in filters.items()}
    response = vault.list(filters_eval, size=100)
    assert len([x for x in response.result.items if x.type != "folder"]) == num_results


# TODO: folders

# TODO: needs improvement
def test_list_pagination(vault: Vault, test_name, list_symmetric_keys):
    response = vault.list({"folder": f"/{test_name}/"}, size=1)
    total = len(response.result.items)
    count = response.result.count

    while response.result.last is not None:
        response = vault.list({"folder": f"/{test_name}/"}, size=1, last=response.result.last)
        total += len(response.result.items)
    assert count == total


# TODO: needs improvement
@pytest.mark.skip("list order not working yet")
def test_list_order(vault: Vault, test_name, list_symmetric_keys):
    response = vault.list(filter={"folder": test_name}, order_by="name", size=10)
    for curr, next in zip(response.result.items, response.result.items[1:]):
        assert curr.name >= next.name

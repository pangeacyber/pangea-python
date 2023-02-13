from base64 import b64encode

import pangea.exceptions as pexc
import pytest
from pangea.services.vault.models.asymmetric import AsymmetricAlgorithm
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
def canonical_asymmetric_args():
    return {
        "algorithm": "ed25519",
        "managed": False,
        "private_key": "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIGthqegkjgddRAn0PWN2FeYC6HcCVQf/Ph9sUbeprTBO\n-----END PRIVATE KEY-----\n",
        "public_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAPlGrDliJXUbPc2YWEhFxlL2UbBfLHc3ed1f36FrDtTc=\n-----END PUBLIC KEY-----\n",
    }


def _asymmetric_key(vault: Vault, key_type, test_name, canonical_args, item_name):
    func = eval(f"vault_item_{item_name}")
    store_func = eval(f"vault.{key_type}_store")
    key_id = func(vault, store_func, f"{test_name}_{key_type}", canonical_args)
    return key_id


@pytest.fixture
def temp_asymmetric_key(vault: Vault, test_name, canonical_asymmetric_args, request):
    key_id = _asymmetric_key(vault, "asymmetric", test_name, canonical_asymmetric_args, getattr(request, "param", "ok"))
    yield key_id
    try:
        vault.delete(key_id)
    except:
        pass


@pytest.fixture(scope="session")
def session_asymmetric_key(vault: Vault, test_name, canonical_asymmetric_args, request):
    name = getattr(request, "param", "ok")
    key_id = _asymmetric_key(vault, "asymmetric", f"{test_name}_session", canonical_asymmetric_args, name)
    yield key_id
    try:
        vault.delete(key_id)
    except:
        pass


@pytest.fixture(scope="session")
def signature(vault: Vault, canonical_asymmetric_args, plain_text, test_name) -> str:
    return vault.sign(
        _asymmetric_key(vault, "asymmetric", test_name, canonical_asymmetric_args, "ok"), plain_text
    ).result.signature


@pytest.mark.parametrize(("param_name", "param_value", "param_response"), create_or_store_key_params)
def test_create_asymmetric(vault: Vault, param_name, param_value, param_response):
    req = {
        "algorithm": AsymmetricAlgorithm.Ed25519,
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

    response = vault.asymmetric_generate(**req)
    key_id = response.result.id

    try:
        response = vault.get(key_id, verbose=True)
        assert getattr(response.result, param_name) == param_response
    finally:
        vault.delete(key_id)


@pytest.mark.parametrize(("param_name", "param_value", "param_response"), create_or_store_key_params)
def test_store_asymmetric(vault: Vault, canonical_asymmetric_args, param_name, param_value, param_response):
    req = {
        "algorithm": AsymmetricAlgorithm.Ed25519,
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
    req["public_key"] = canonical_asymmetric_args["public_key"]
    req["private_key"] = canonical_asymmetric_args["private_key"]
    req[param_name] = param_value

    response = vault.asymmetric_store(**req)
    key_id = response.result.id

    try:
        response = vault.get(key_id, verbose=True)
        assert getattr(response.result, param_name) == param_response
    finally:
        vault.delete(key_id)


@pytest.mark.parametrize(
    ("session_asymmetric_key", "ok"),
    [
        ("expired", False),
        ("revoked", False),
        ("ok", True),
    ],
    indirect=["session_asymmetric_key"],
)
def test_sign_keys(vault: Vault, session_asymmetric_key, plain_text, ok):
    if ok:
        vault.sign(session_asymmetric_key, plain_text)
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.sign(session_asymmetric_key, plain_text)


@pytest.mark.parametrize(
    ("plain_text", "ok"),
    [
        (b64encode(b"hello").decode(), True),
        ("hello", False),
    ],
    ids=["ok", "not base64"],
)
def test_sign_params(vault: Vault, session_asymmetric_key, plain_text, ok):
    if ok:
        vault.sign(session_asymmetric_key, plain_text)
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.sign(session_asymmetric_key, plain_text)


@pytest.mark.parametrize(
    ("session_asymmetric_key"),
    [
        "expired",
        "revoked",
        "ok",
    ],
    indirect=True,
)
def test_verify(vault: Vault, session_asymmetric_key, plain_text, signature):
    resp = vault.verify(session_asymmetric_key, plain_text, signature)
    assert resp.result.valid_signature


@pytest.mark.skip("encrypting with asymmetric not working yet")
@pytest.mark.parametrize(
    ("session_asymmetric_key", "ok"),
    [
        ("expired", False),
        ("revoked", False),
        ("ok", True),
    ],
)
def test_encrypt(vault: Vault, session_asymmetric_key, plain_text, ok):
    if ok:
        vault.encrypt(session_asymmetric_key, plain_text)
    else:
        with pytest.raises(pexc.VaultAPIException):
            vault.encrypt(session_asymmetric_key, plain_text)


@pytest.mark.skip("encrypting with asymmetric not working yet")
@pytest.mark.parametrize(
    ("key_name"),
    [
        "expired",
        "revoked",
        "ok",
    ],
)
def test_decrypt(vault: Vault, session_asymmetric_key, plain_text, cipher_text, key_name):
    response = vault.decrypt(session_asymmetric_key[key_name], cipher_text)
    assert response.result.plain_text == plain_text


@pytest.mark.parametrize(("param_name", "param_value", "param_response"), update_params)
def test_update_attributes_asymmetric(vault: Vault, temp_asymmetric_key, param_name, param_value, param_response):
    req = {"id": temp_asymmetric_key, param_name: param_value}

    response = vault.update(**req)
    key_id = response.result.id

    response = vault.get(key_id, verbose=True)
    assert getattr(response.result, param_name) == param_response


@pytest.mark.parametrize(
    ("temp_asymmetric_key", "ok"),
    [
        ("ok", True),
        ("expired", False),
        ("revoked", False),
    ],
    indirect=["temp_asymmetric_key"],
)
def test_update_keys_asymmetric(vault: Vault, temp_asymmetric_key, ok):
    if ok:
        vault.update(id=temp_asymmetric_key, tags=["pepe"])
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.update(id=temp_asymmetric_key, tags=["pepe"])


@pytest.mark.parametrize(
    ("temp_asymmetric_key", "ok"),
    [
        ("ok", True),
        ("missing", False),
        ("expired", True),
        ("revoked", False),
    ],
    indirect=["temp_asymmetric_key"],
)
def test_rotate_keys_asymmetric(vault: Vault, temp_asymmetric_key, ok):
    if ok:
        vault.key_rotate(temp_asymmetric_key)
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.key_rotate(temp_asymmetric_key)


@pytest.mark.parametrize(
    ("params", "ok"),
    [
        (
            {
                "public_key": "canonical_asymmetric_args['public_key']",
                "private_key": "canonical_asymmetric_args['private_key']",
            },
            True,
        ),
        ({"public_key": "None", "private_key": "None"}, True),
        ({"public_key": "canonical_asymmetric_args['public_key']", "private_key": "None"}, False),
        ({"public_key": "None", "private_key": "canonical_asymmetric_args['private_key']"}, False),
        ({"public_key": "'xxx'", "private_key": "canonical_asymmetric_args['private_key']"}, False),
    ],
    ids=[
        "both",
        "none",
        "one",
        "other",
        "wrong",
    ],
)
def test_rotate_params_asymmetric(vault: Vault, temp_asymmetric_key, canonical_asymmetric_args, params, ok):
    args = {
        "id": temp_asymmetric_key,
        "public_key": eval(params["public_key"]),
        "private_key": eval(params["private_key"]),
    }

    if ok:
        prev_version = vault.get(id=temp_asymmetric_key).result.version
        vault.key_rotate(**args)
        curr_version = vault.get(id=temp_asymmetric_key).result.version
        assert curr_version == prev_version + 1

    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.key_rotate(**args)


@pytest.mark.parametrize(
    ("temp_asymmetric_key", "ok"),
    [("expired", False), ("revoked", False), ("missing", False), ("ok", True)],
    indirect=["temp_asymmetric_key"],
)
def test_revoke(vault: Vault, temp_asymmetric_key, ok):
    if ok:
        vault.revoke(temp_asymmetric_key)
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.revoke(temp_asymmetric_key)


@pytest.mark.parametrize(
    ("temp_asymmetric_key", "ok"),
    [
        ("expired", True),
        ("revoked", True),
        ("ok", True),
        ("missing", False),
    ],
    indirect=["temp_asymmetric_key"],
)
def test_delete(vault: Vault, temp_asymmetric_key, ok):
    if ok:
        vault.delete(temp_asymmetric_key)
        with pytest.raises(pexc.PangeaAPIException):
            vault.get(temp_asymmetric_key)
    else:
        with pytest.raises(pexc.PangeaAPIException):
            vault.delete(temp_asymmetric_key)


@pytest.fixture(scope="session")
def list_asymmetric_keys(vault: Vault, test_name, canonical_asymmetric_args):
    keys = [
        _asymmetric_key(vault, "asymmetric", f"{test_name}_list", canonical_asymmetric_args, name)
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
        ({"name": "{test_name}_list_asymmetric_ok"}, 1),
        ({"name": "xxx"}, 0),
        ({"name__contains": "{test_name}_list_asymmetric"}, 3),
        ({"folder": "/{test_name}_list_asymmetric/"}, 3),
        # TODO: add more!
    ],
    ids=[
        "name exact",
        "name not found",
        "name contains",
        "folder",
    ],
)
def test_list_filter(vault: Vault, test_name, list_asymmetric_keys, filters, num_results):
    filters_eval = {k: v.replace("{test_name}", test_name) for k, v in filters.items()}
    response = vault.list(filters_eval, size=100)
    assert len([x for x in response.result.items if x.type != "folder"]) == num_results


# TODO: folders

# TODO: needs improvement
def test_list_pagination(vault: Vault, test_name, list_asymmetric_keys):
    response = vault.list({"folder": f"/{test_name}/"}, size=1)
    total = len(response.result.items)
    count = response.result.count

    while response.result.last is not None:
        response = vault.list({"folder": f"/{test_name}/"}, size=1, last=response.result.last)
        total += len(response.result.items)
    assert count == total


# TODO: needs improvement
@pytest.mark.skip("list order not working yet")
def test_list_order(vault: Vault, test_name, list_asymmetric_keys):
    response = vault.list(filter={"folder": test_name}, order_by="name", size=10)
    for curr, next in zip(response.result.items, response.result.items[1:]):
        assert curr.name >= next.name

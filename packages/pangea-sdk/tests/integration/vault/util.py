import time
import typing as t
from datetime import datetime, timedelta
from itertools import chain


def make_pairs(name: str, values: list, results: t.Optional[list] = None):
    if results is None:
        results = values
    return [(name, value, result) for value, result in zip(values, results)]


create_or_store_params = list(
    chain(
        make_pairs("name", ["Diego", "", None]),
        make_pairs("folder", ["/tmp/xxx", "/", None], ["/tmp/xxx/", "/", "/"]),
        make_pairs("metadata", [None, {}, {"owner": "diego"}], [{}, {}, {"owner": "diego"}]),
        make_pairs("tags", [None, [], ["tag1", "tag2"]], [[], [], ["tag1", "tag2"]]),
        make_pairs("expiration", [None, "2025-01-01T10:30:00Z"]),
    )
)


create_or_store_key_params = create_or_store_params + list(
    chain(
        make_pairs("managed", [True, False]),
    )
)


update_params = list(
    chain(
        make_pairs("name", ["Diego", ""]),  # TODO: add None
        make_pairs(
            "folder", ["/tmp/xxx/", "/"], ["/tmp/xxx/", "/"]
        ),  # TODO: add None, remove trailing slash and check result
        make_pairs("metadata", [None, {}, {"owner": "diego"}], [{}, {}, {"owner": "diego"}]),
        make_pairs("tags", [None, [], ["tag1", "tag2"]], [[], [], ["tag1", "tag2"]]),
        make_pairs("expiration", [None, "2025-01-01T10:30:00Z"]),
    )
)

# TODO: rotation_policy, store, retain_previous_version


def copy_item(store_func, item_name, folder_name, extra_args={}):
    return store_func(name=item_name, folder=folder_name, **extra_args).result


def vault_item_ok(vault, store_func, item_name, extra_args):
    return copy_item(store_func, f"{item_name}_ok", item_name, extra_args).id


def vault_item_expired(vault, store_func, item_name, extra_args):
    extra_args_exp = extra_args.copy()
    extra_args_exp["expiration"] = datetime.now() + timedelta(seconds=1)
    key_id = copy_item(store_func, f"{item_name}_expired", item_name, extra_args_exp).id
    time.sleep(1)
    return key_id


def vault_item_revoked(vault, store_func, item_name, extra_args):
    key_id = copy_item(store_func, f"{item_name}_revoked", item_name, extra_args).id
    vault.revoke(key_id)
    return key_id


def vault_item_missing(vault, store_func, item_name, extra_args):
    return "xxx"

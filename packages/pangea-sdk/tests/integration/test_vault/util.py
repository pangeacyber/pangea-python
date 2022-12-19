from itertools import chain
import typing as t


def make_pairs(name: str, values: list, results: t.Optional[list] = None):
    if results is None:
        results = values
    return [(name, value, result) for value, result in zip(values, results)]


create_or_store_params = list(chain(
    make_pairs("name", ["Diego", "", None]),
    make_pairs("folder", ["/tmp/xxx", "/", None], ["/tmp/xxx/", "/", "/"]),
    make_pairs("metadata", [None, {}, {"owner": "diego"}], [{}, {}, {"owner": "diego"}]),
    make_pairs("tags", [None, [], ["tag1", "tag2"]], [[], [], ["tag1", "tag2"]]),
    make_pairs("expiration", [None, "2025-01-01T10:30:00Z"])
))


create_or_store_key_params = create_or_store_params + list(chain(
    make_pairs("managed", [True, False]),
))


update_params = list(chain(
    make_pairs("name", ["Diego", "", None]),
    make_pairs("folder", ["/tmp/xxx", "/", None], ["/tmp/xxx/", "/", "/"]),
    make_pairs("metadata", [None, {}, {"owner": "diego"}], [{}, {}, {"owner": "diego"}]),
    make_pairs("tags", [None, [], ["tag1", "tag2"]], [[], [], ["tag1", "tag2"]]),
    make_pairs("expiration", [None, "2025-01-01T10:30:00Z"])
))

# TODO: rotation_policy, store

    #make_pairs("retain_previous_version", [True, False]),

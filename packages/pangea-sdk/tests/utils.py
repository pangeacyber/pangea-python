from __future__ import annotations

import sys
import traceback
import typing
from typing import TYPE_CHECKING, Any, cast

import typing_extensions
from pydantic import BaseModel
from pydantic.v1.typing import get_args, is_union
from typing_extensions import TypeGuard, TypeIs, TypeVar, assert_type, get_origin

__all__ = ("assert_matches_type",)


if TYPE_CHECKING:
    NoneType: type[None]
else:
    NoneType = type(None)


BaseModelT = TypeVar("BaseModelT", bound=BaseModel)


def is_dict(obj: object) -> TypeGuard[dict[object, object]]:
    return isinstance(obj, dict)


def is_list(obj: object) -> TypeGuard[list[object]]:
    return isinstance(obj, list)


def is_list_type(typ: type) -> bool:
    return (get_origin(typ) or typ) is list


def is_union_type(typ: type) -> bool:
    return is_union(get_origin(typ))


def assert_matches_model(model: type[BaseModelT], value: BaseModelT, *, path: list[str]) -> bool:
    for name, field in model.model_fields.items():
        field_value = getattr(value, name)
        assert_matches_type(
            field.annotation,
            field_value,
            path=[*path, name],
            allow_none=False,
        )

    return True


def _assert_list_type(type_: type[object], value: object) -> None:
    assert is_list(value)

    inner_type = get_args(type_)[0]
    for entry in value:
        assert_type(inner_type, entry)  # type: ignore


_TYPE_ALIAS_TYPES: tuple[type[typing_extensions.TypeAliasType], ...] = (typing_extensions.TypeAliasType,)
if sys.version_info >= (3, 12):
    _TYPE_ALIAS_TYPES = (*_TYPE_ALIAS_TYPES, typing.TypeAliasType)


def is_type_alias_type(tp: Any, /) -> TypeIs[typing_extensions.TypeAliasType]:
    return isinstance(tp, _TYPE_ALIAS_TYPES)


def is_typevar(typ: type) -> bool:
    return type(typ) is TypeVar


def assert_matches_type(
    type_: Any,
    value: object,
    *,
    path: list[str],
    allow_none: bool = False,
) -> None:
    if is_type_alias_type(type_):
        type_ = type_.__value__

    if allow_none and value is None:
        return

    if type_ is None or type_ is NoneType:
        assert value is None
        return

    origin = get_origin(type_) or type_

    if is_list_type(type_):
        return _assert_list_type(type_, value)

    if origin is str:
        assert isinstance(value, str)
    elif origin is int:
        assert isinstance(value, int)
    elif origin is bool:
        assert isinstance(value, bool)
    elif origin is object:
        # Expected unknown type.
        pass
    elif origin is dict:
        assert is_dict(value)

        args = get_args(type_)
        key_type = args[0]
        items_type = args[1]

        for key, item in value.items():
            assert_matches_type(key_type, key, path=[*path, "<dict key>"])
            assert_matches_type(items_type, item, path=[*path, "<dict item>"])
    elif is_union_type(type_):
        variants = get_args(type_)

        try:
            none_index = variants.index(type(None))
        except ValueError:
            pass
        else:
            if len(variants) == 2:
                if value is None:
                    return

                return assert_matches_type(type_=variants[not none_index], value=value, path=path)

        for i, variant in enumerate(variants):
            try:
                assert_matches_type(variant, value, path=[*path, f"variant {i}"])
                return
            except AssertionError:
                traceback.print_exc()
                continue

        raise AssertionError("Did not match any variants")
    elif issubclass(origin, BaseModel):
        assert isinstance(value, type_)
        assert assert_matches_model(type_, cast(Any, value), path=path)
    elif isinstance(origin, TypeVar):
        pass
    else:
        assert None, f"Unhandled field type: {type_}"

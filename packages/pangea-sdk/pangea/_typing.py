from __future__ import annotations

from collections.abc import Iterator, Sequence

from typing_extensions import Any, Protocol, SupportsIndex, TypeVar, overload

T = TypeVar("T")
T_co = TypeVar("T_co", covariant=True)


class SequenceNotStr(Protocol[T_co]):
    """Sequence-like object that isn't str or bytes."""

    @overload
    def __getitem__(self, index: SupportsIndex, /) -> T_co: ...

    @overload
    def __getitem__(self, index: slice, /) -> Sequence[T_co]: ...

    def __contains__(self, value: object, /) -> bool: ...

    def __len__(self) -> int: ...

    def __iter__(self) -> Iterator[T_co]: ...

    def index(self, value: Any, start: int = ..., stop: int = ..., /) -> int: ...

    def count(self, value: Any, /) -> int: ...

    def __reversed__(self) -> Iterator[T_co]: ...

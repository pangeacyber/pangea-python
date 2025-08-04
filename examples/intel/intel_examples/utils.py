from __future__ import annotations

from collections.abc import Mapping

from pangea.services.intel import IntelReputationData

__all__ = ("print_reputation_bulk_data", "print_reputation_data")


def print_reputation_data(indicator: str, data: IntelReputationData) -> None:
    print(f"\tIndicator: {indicator}")
    print(f"\t\tVerdict: {data.verdict}")
    print(f"\t\tScore: {data.score}")
    print(f"\t\tCategory: {data.category}")


def print_reputation_bulk_data(data: Mapping[str, IntelReputationData]) -> None:
    for k, v in data.items():
        print_reputation_data(k, v)

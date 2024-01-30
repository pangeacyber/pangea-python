from typing import Dict

from pangea.services.intel import IntelReputationData


def print_reputation_data(indicator: str, data: IntelReputationData) -> None:
    print(f"\tIndicator: {indicator}")
    print(f"\t\tVerdict: {data.verdict}")
    print(f"\t\tScore: {data.score}")
    print(f"\t\tCategory: {data.category}")


def print_reputation_bulk_data(data: Dict[str, IntelReputationData]) -> None:
    for k, v in data.items():
        print_reputation_data(k, v)

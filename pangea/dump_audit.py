"""
Command-line tool for dumping audit events.

Usage: python dump_audit.py <datetime_from> <datetime_to> 

    -f filename: output file prefix

Datetimes should be in ISO 8601 format.
"""

import json
import os
import argparse
from typing import Optional
from datetime import datetime, timezone
from dateutil.parser import parse

from pangea.config import PangeaConfig
from pangea.services import Audit


def print_progress_bar(iteration, total, prefix="", suffix="", decimals=1, length=100):
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = "█" * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end="\r")
    if iteration == total:
        print()


def dump_audit(audit: Audit, fname: str, start: datetime, end: datetime) -> int:
    offset = 0
    page_end = start
    with open(f"{fname}.jsonl", "w") as file:
        found_any = dump_before(audit, file, start) > 0
        while True:
            page_end, page_size = dump_page(audit, file, page_end, end, first=not found_any)
            if page_size == 0:
                break
            offset += page_size
        dump_after(audit, file, end)
    return offset


def dump_before(audit: Audit, file, start: datetime) -> int:
    print("Dumping before...", end="\r")
    search_res = audit.search(
        start="2000-01-01T10:00:00Z",
        end=start.isoformat(),
        order="desc",
        verify=False,
        limit=1000,
        max_results=1000
    )
    if not search_res.success:
        raise ValueError("Error fetching events")

    with open(f"{os.path.splitext(file.name)[0]}.root.json", "w") as out_root:
        out_root.write(json.dumps(search_res.result.root))

    cnt = 0
    if search_res.result.count > 0:
        leaf_index = search_res.result.events[0].leaf_index
        for row in reversed(search_res.result.events):
            if row.leaf_index != leaf_index:
                break
            file.write(json.dumps(row) + "\n")
            cnt += 1
    print(f"Dumping before... {cnt} events")
    return cnt


def dump_after(audit: Audit, file, start: datetime):
    print("Dumping after...", end="\r")
    search_res = audit.search(
        start=start.isoformat(),
        order="asc",
        verify=False,
        limit=1000,
        max_results=1000
    )
    if not search_res.success:
        raise ValueError("Error fetching events")

    if search_res.result.count > 0:
        cnt = 0
        leaf_index = search_res.result.events[0].leaf_index
        for row in search_res.result.events[1:]:
            if row.leaf_index != leaf_index:
                break
            file.write(json.dumps(row) + "\n")
            cnt += 1
        print(f"Dumping after... {cnt} events")


def dump_page(audit: Audit, file, start: datetime, end: datetime, first: bool = False) -> tuple[datetime, int]:
    print("Dumping...", end="\r")
    search_res = audit.search(
        start=start.isoformat(),
        end=end.isoformat(),
        order="asc",
        verify=False,
        limit=1000
    )
    if not search_res.success:
        raise ValueError("Error fetching events")

    msg = f"Dumping... {search_res.result.count} events"

    if search_res.result.count <= 1:
        return end, 0

    offset = 0
    result_id = search_res.result.id
    count = search_res.result.count
    while offset < count:
        for row in search_res.result.events:
            if first or offset > 0:
                file.write(json.dumps(row) + "\n")
            offset += 1
        if offset < count:
            search_res = audit.results(result_id, offset=offset)
            if not search_res.success:
                raise ValueError("Error fetching events")
        print_progress_bar(offset, count, prefix=msg, suffix="Complete", length=50)

    page_end = parse(row.event.received_at)
    return page_end, offset


def init_audit(token: Optional[str], config_id: Optional[str], base_domain: Optional[str]) -> Audit:
    token = token or os.getenv("PANGEA_TOKEN")
    if token is None:
        raise ValueError("Missing pangea token")

    config_id = config_id or os.getenv("AUDIT_CONFIG_ID")
    # if config_id is None:
    #     raise ValueError("Missing Audit Config ID")

    base_domain = base_domain or os.getenv("PANGEA_BASE_DOMAIN", "dev.pangea.cloud")

    config = PangeaConfig(base_domain=base_domain, config_id=config_id)
    audit = Audit(token, config=config)
    return audit


def main():
    parser = argparse.ArgumentParser(description="Pangea Audit Dump")
    parser.add_argument("--token", help="Pangea token")
    parser.add_argument("--base-domain", help="Pangea base domain")
    parser.add_argument("--config-id", help="Audit config id")
    parser.add_argument("--file", "-f", default="dump", help="Output file name (without extension)")
    parser.add_argument('start', help='start timestamp')
    parser.add_argument('end', help='end timestamp')
    args = parser.parse_args()

    start = parse(args.start)
    if start.tzinfo is None:
        start = start.astimezone(timezone.utc)
    end = parse(args.end)
    if end.tzinfo is None:
        end = end.astimezone(timezone.utc)

    fname = args.file

    audit = init_audit(args.token, args.config_id, args.base_domain)
    dump_audit(audit, fname, start, end)
    print("\nDone.")


if __name__ == "__main__":
    main()

# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation

import argparse
import io
import json
import os
import sys
from datetime import datetime

import dateutil.parser
from pangea.response import PangeaResponse
from pangea.services import Audit
from pangea.tools_util import (
    filter_deep_none,
    get_script_name,
    init_audit,
    json_defaults,
    make_aware_datetime,
    print_progress_bar,
)


def dump_event(output: io.TextIOWrapper, row: dict, resp: PangeaResponse):
    row_data = filter_deep_none(row.dict())
    if resp.result.root:
        row_data["tree_size"] = resp.result.root.size
    output.write(json.dumps(row_data, default=json_defaults) + "\n")


def dump_audit(audit: Audit, output: io.TextIOWrapper, start: datetime, end: datetime) -> int:
    """
    Use the /search endpoint to download all the events from a range of time.
    Also extend the range in both directions to cover full buffers.
    """
    offset = 0
    page_end = start
    offset = dump_before(audit, output, start)
    while True:
        page_end, page_size, stop, last_hash, last_leaf_index = dump_page(
            audit, output, page_end, end, first=offset == 0
        )
        if stop:
            break
        offset += page_size
    print()
    offset += dump_after(audit, output, end, last_hash, last_leaf_index)
    return offset


def dump_before(audit: Audit, output: io.TextIOWrapper, start: datetime) -> int:
    print("Dumping before...")
    search_res = audit.search(
        query="",
        start=datetime.strptime("2020-01-01T10:00:00Z", "%Y-%m-%dT%H:%M:%SZ"),
        end=start,
        order="desc",
        verify_consistency=False,
        limit=1000,
        max_results=1000,
        verify_events=False,
    )
    if not search_res.success:
        raise ValueError(f"Error fetching events: {search_res.result}")

    cnt = 0
    if search_res.result.count > 0:
        leaf_index = search_res.result.events[0].leaf_index
        for row in reversed(search_res.result.events):
            if row.leaf_index != leaf_index:
                break
            dump_event(output, row, search_res)
            cnt += 1
    print(f"Dumping before... {cnt} events")
    return cnt


def dump_after(audit: Audit, output: io.TextIOWrapper, start: datetime, last_event_hash, last_leaf_index) -> int:
    print("Dumping after...", end="\r")
    search_res = audit.search(
        query="", start=start, order="asc", verify_consistency=False, limit=1000, max_results=1000, verify_events=False
    )
    if not search_res.success:
        raise ValueError("Error fetching events")

    cnt = 0
    if search_res.result.count > 0:
        leaf_index = search_res.result.events[0].leaf_index
        if leaf_index == last_leaf_index:
            start = 1 if last_event_hash == search_res.result.events[0].hash else 0
            for row in search_res.result.events[start:]:
                if row.leaf_index != leaf_index:
                    break
                dump_event(output, row, search_res)
                cnt += 1
    print(f"Dumping after... {cnt} events")
    return cnt


def dump_page(
    audit: Audit, output: io.TextIOWrapper, start: datetime, end: datetime, first: bool = False
) -> tuple[datetime, int, bool, str, int]:
    PAGE_SIZE = 1000
    print(start, end)
    print("Dumping...")
    search_res = audit.search(
        query="",
        start=start,
        end=end,
        order="asc",
        order_by="received_at",
        verify_consistency=False,
        verify_events=False,
        limit=PAGE_SIZE,
    )
    if not search_res.success:
        raise ValueError(f"Error fetching events: {search_res.result}")

    msg = f"Dumping... {search_res.result.count} events"

    if search_res.result.count <= 1:
        return end, 0

    offset = 0
    result_id = search_res.result.id
    count = search_res.result.count
    while offset < count:
        for row in search_res.result.events:
            if first or offset > 0:
                dump_event(output, row, search_res)
            offset += 1
        if offset < count:
            search_res = audit.results(result_id, offset=offset, verify_events=False)
            if not search_res.success:
                raise ValueError("Error fetching events")
        print_progress_bar(offset, count, prefix=msg, suffix="Complete", length=50)
    page_end = row.envelope.received_at
    return page_end, offset, search_res.result.count < PAGE_SIZE, row.hash, row.leaf_index


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Pangea Audit Dump Tool")
    parser.add_argument(
        "--token", "-t", default=os.getenv("PANGEA_TOKEN"), help="Pangea token (default: env PANGEA_TOKEN)"
    )
    parser.add_argument(
        "--domain", "-d", default=os.getenv("PANGEA_DOMAIN"), help="Pangea domain (default: env PANGEA_DOMAIN)"
    )
    parser.add_argument("--output", "-o", type=argparse.FileType("w"), help="Output file name. Default: stdout")
    parser.add_argument(
        "start", type=dateutil.parser.parse, help="Start timestamp. Supports a variety of formats, including ISO-8601"
    )
    parser.add_argument(
        "end", type=dateutil.parser.parse, help="End timestamp. Supports a variety of formats, including ISO-8601"
    )

    return parser


def parse_args(parser: argparse.ArgumentParser):
    args = parser.parse_args()

    if not args.token:
        raise ValueError("token missing")

    if not args.domain:
        raise ValueError("domain missing")

    if args.output is None:
        args.output = open(f"dump-{datetime.now().strftime('%Y%m%d%H%M%S')}.jsonl", "w")

    args.start = make_aware_datetime(args.start)
    args.end = make_aware_datetime(args.end)

    if args.start > args.end:
        raise ValueError("start_date must be before than end_date")

    return args


def main():
    parser = create_parser()
    try:
        args = parse_args(parser)
    except Exception as e:
        parser.print_usage()
        print(f"{get_script_name()}: error: {str(e)}")
        sys.exit(-1)

    print("Pangea Audit Dump Tool\n")

    try:
        audit = init_audit(args.token, args.domain)
        cnt = dump_audit(audit, args.output, args.start, args.end)
        print(f"\nFile {args.output.name} created with {cnt} events.")

    except Exception as e:
        print(f"{get_script_name()}: error: {str(e)}")
        sys.exit(-1)

    print("Done.")
    sys.exit(0)


if __name__ == "__main__":
    main()

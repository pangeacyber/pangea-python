import datetime
import os

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.response import PangeaResponse
from pangea.services import Audit
from pangea.services.audit.audit import SearchOutput, SearchResultOutput
from pangea.tools import logger_set_pangea_config

# This example shows how to perform an audit log, and then search through the results.

token = os.getenv("PANGEA_AUDIT_CUSTOM_SCHEMA_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
audit = Audit(token, config=config, private_key_file="./key/privkey", logger_name="audit")
logger_set_pangea_config(logger_name=audit.logger.name)

msg = "python-sdk-custom-schema-example"

custom_schema_event = {
    "message": msg,
    "field_int": 1,
    "field_bool": True,
    "field_str_short": "python-sdk-signed",
    "field_str_long": "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed lacinia, orci eget commodo commodo non.",
    "field_time": datetime.datetime.now(),
}


def main():
    print("Log Data...")

    try:
        log_response = audit.log_event(
            event=custom_schema_event,
            verify=True,
            verbose=False,
            sign_local=True,
        )
        print(f"Log Request ID: {log_response.request_id}, Status: {log_response.status}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")
        exit()

    print("Search Data...")

    page_size = 10
    query = "message:" + msg

    try:
        search_res: PangeaResponse[SearchOutput] = audit.search(
            query=query, limit=page_size, verify_consistency=True, verify_events=True
        )

        result_id = search_res.result.id
        count = search_res.result.count
        print(f"Search Request ID: {search_res.request_id}, Success: {search_res.status}, Results: {count}")
        offset = 0

        print_header_results()
        while offset < count:
            print_page_results(search_res, offset, count)
            offset += page_size

            if offset < count:
                search_res = audit.results(
                    id=result_id, limit=page_size, offset=offset, verify_consistency=True, verify_events=True
                )

    except pe.PangeaAPIException as e:
        print("Search Failed:", e.response.summary)
        for err in e.errors:
            print(f"\t{err.detail} \n")


def print_header_results():
    print(f"\n\nreceived_at\t\t\t\tMessage \t\tMembership \tConsistency \tSignature\t")


def print_page_results(search_res: PangeaResponse[SearchResultOutput], offset, count):
    print("\n--------------------------------------------------------------------\n")
    for row in search_res.result.events:
        print(
            f"{row.envelope.received_at}\t{row.envelope.event['message']}\t{row.membership_verification}\t\t {row.consistency_verification}\t\t {row.signature_verification}\t\t"
        )
    print(
        f"\nResults: {offset+1}-{offset+len(search_res.result.events)} of {count}",
    )


if __name__ == "__main__":
    main()

import os

from pangea.config import PangeaConfig
from pangea.exceptions import AuditException
from pangea.response import PangeaResponse
from pangea.services import Audit
from pangea.services.audit import (
    Event,
    SearchInput,
    SearchOutput,
    SearchRestriction,
    SearchResultInput,
    SearchResultOutput,
)

token = os.getenv("AUDIT_AUTH_TOKEN")
config_id = os.getenv("AUDIT_CONFIG_ID")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain, config_id=config_id)
audit = Audit(
    token, config=config, enable_signing=True, private_key_file="./tests/testdata/privkey", verify_response=True
)


def main():
    print("Log Data...")
    event = Event(
        message="Hello world",
        actor="Someone",
        action="Testing",
        source="monitor",
        status="Good",
        target="Another spot",
        new="New updated message",
        old="Old message that it's been updated",
    )

    print(f"Logging: {event.dict(exclude_none=True)}")

    try:
        log_response = audit.log(event=event, verify=True, verbose=False, signing=True)
        print(f"Log Request ID: {log_response.request_id}, Status: {log_response.status}")
    except AuditException as e:
        print(f"Log Request Error: {e.message}")
        exit()

    print("Search Data...")

    page_size = 10

    query = "message:" + event.message
    restriction = SearchRestriction(source=["monitor"])

    search_input = SearchInput(query=query, search_restriction=restriction, limit=page_size)
    search_res = audit.search(input=search_input, verify=True, verify_signatures=True)

    if search_res.success:
        result_id = search_res.result.id
        count = search_res.result.count
        print(f"Search Request ID: {search_res.request_id}, Success: {search_res.status}, Results: {count}")
        offset = 0

        while offset < count:
            print_page_results(search_res, offset, count)
            offset += page_size

            if offset < count:
                res_input = SearchResultInput(id=result_id, limit=page_size, offset=offset)
                search_res = audit.results(input=res_input, verify_signatures=True)

    else:
        print("Search Failed:", search_res.status_code)
        # FIXME: check what info we do have when fails
        for err in search_res.result.errors:
            print(f"\t{err.detail}")
        print("")


def print_page_results(search_res: PangeaResponse[SearchResultOutput], offset, count):
    print("\n--------------------------------------------------------------------\n")
    for row in search_res.result.events:
        print(
            f"{row.envelope.received_at}\t{row.envelope.event.message}\t{row.envelope.event.source}"
            f"\t{row.envelope.event.actor}\t\t{row.membership_verification} {row.consistency_verification} {row.signature_verification}"
        )
    print(
        f"\nResults: {offset+1}-{offset+len(search_res.result.events)} of {count}",
    )


if __name__ == "__main__":
    main()

import os

from pangea.config import PangeaConfig
from pangea.services import Audit

token = os.getenv("PANGEA_TOKEN")
config_id = os.getenv("AUDIT_CONFIG_ID")
config = PangeaConfig(base_domain="dev.pangea.cloud", config_id=config_id)
audit = Audit(token, config=config)

data = {
    "action": "reboot",
    "actor": "villain",
    "target": "world",
    "status": "error",
    "message": "test",
    "source": "monitor",
}


def main():
    # print("Log Data...")
    # log_response = audit.log(data)
    # if log_response.success:
    #     print(
    #         f"Log Request ID: {log_response.request_id}, Success: {log_response.status}"
    #     )
    # else:
    #     print(f"Log Request Error: {log_response.response.text}")
    #     if log_response.result and log_response.result.errors:
    #         for err in log_response.result.errors:
    #             print(f"\t{err.detail}")
    #         print("")

    print("Search Data...")

    page_size = 10

    search_res = audit.search(
        query="message:test",
        restriction={"source": ["monitor"]},
        limit=page_size,
        verify=False,
    )
    if search_res.success:
        result_id = search_res.result.id
        count = search_res.result.count
        print(f"Search Request ID: {search_res.request_id}, Success: {search_res.status}, Results: {count}")
        pub_roots = {}
        offset = 0

        while offset < count:
            audit.update_published_roots(pub_roots, search_res.result)
            print_page_results(pub_roots, search_res, offset, count)
            offset += page_size

            search_res = audit.results(result_id, limit=page_size, offset=offset)

    else:
        print("Search Failed:", search_res.code)
        for err in search_res.result.errors:
            print(f"\t{err.detail}")
        print("")


def membership_verification(audit, root, row):
    if not audit.can_verify_membership_proof(row):
        return "o"
    elif audit.verify_membership_proof(root, row):
        return "✓"
    else:
        return "x"


def consistency_verification(audit, pub_roots, row):
    if not audit.can_verify_consistency_proof(row):
        return "o"
    elif audit.verify_consistency_proof(pub_roots, row):
        return "✓"
    else:
        return "x"


def signature_verification(row):
    if audit.verify_signature(row):
        return "✓"
    else:
        return "x"


def print_page_results(pub_roots, search_res, offset, count):
    root = search_res.result.root
    print("\n--------------------------------------------------------------------\n")
    for row in search_res.result.events:
        membership = membership_verification(audit, root, row)
        consistency = consistency_verification(audit, pub_roots, row)
        # signature = signature_verification(row)
        print(
            f"{row.event.received_at}\t{row.event.message}\t{row.event.source}"
            f"\t{row.event.actor}\t\t{membership} {consistency}"
        )
    print(
        f"\nResults: {offset+1}-{offset+len(search_res.result.events)} of {count}",
    )


if __name__ == "__main__":
    main()

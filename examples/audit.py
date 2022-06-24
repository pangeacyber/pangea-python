import os

from pangea.config import PangeaConfig
from pangea.services import Audit

token = os.getenv("PANGEA_TOKEN")
config_id = os.getenv("AUDIT_CONFIG_ID")
config = PangeaConfig(base_domain="dev.pangea.cloud", config_id=config_id)
audit = Audit(token, config=config)

data = {
    "action": "reboot",
    "actor": "villan",
    "target": "world",
    "status": "error",
    "message": "test",
    "source": "ppi_3tAdYJUiyssGgJJf7B1SbYLpsdPo",
}


def main():
    print("Log Data...")
    log_response = audit.log(data)
    if log_response.success:
        print(
            f"Log Request ID: {log_response.request_id}, Success: {log_response.status}"
        )
    else:
        print(f"Log Request Error: {log_response.response.text}")
        for err in search_res.response.result.errors:
            print(f"\t{err.detail}")
        print("")

    print("Search Data...")
    search_res = audit.search(
        query="message:test",
        sources=["ppi_3tAdYJUiyssGgJJf7B1SbYLpsdPo"],
        page_size=5,
        verify=False,
    )
    if search_res.success:
        print(
            f"Search Request ID: {search_res.request_id}, Success: {search_res.status}"
        )
        pub_roots = {}

        while search_res is not None:
            audit.update_published_roots(pub_roots, search_res.response.result)
            print_page_results(pub_roots, search_res)
            search_res = audit.search_next(search_res)

    else:
        print("Search Failed:", search_res.code)
        for err in search_res.response.result.errors:
            print(f"\t{err.detail}")
        print("")


def membership_verification(audit, root, row):
    if not audit.can_verify_membership_proof(row):
        return "o"
    elif audit.verify_membership_proof(root, row):
        return "."
    else:
        return "x"


def consistency_verification(audit, pub_roots, row):
    if not audit.can_verify_consistency_proof(row):
        return "o"
    elif audit.verify_consistency_proof(pub_roots, row):
        return "."
    else:
        return "x"


def print_page_results(pub_roots, search_res):
    root = search_res.result.root
    print("\n--------------------------------------------------------------------\n")
    for row in search_res.result.events:
        membership = membership_verification(audit, root, row)
        consistency = consistency_verification(audit, pub_roots, row)
        print(
            f"{row.event.message}\t{row.event.created}\t{row.event.source}\t{row.event.actor}\t\t{membership}{consistency}"
        )
    print(
        f"\nResults: {search_res.count} of {search_res.total} - next {search_res.next()}",
    )


if __name__ == "__main__":
    main()

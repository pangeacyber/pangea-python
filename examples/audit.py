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
            f"Search Request ID: {search_res.request_id}, Success: {log_response.status}"
        )

        while search_res is not None:
            print_page_results(search_res)
            search_res = audit.search_next(search_res)

    else:
        print("Search Failed:", search_res.code)
        for err in search_res.response.result.errors:
            print(f"\t{err.detail}")
        print("")


def print_page_results(search_res):
    print("\n--------------------------------------------------------------------\n")
    for row in search_res.result.events:
        print(
            f"{row.event.message}\t{row.event.created}\t{row.event.source}\t{row.event.actor}"
        )
    print(
        f"\nResults: {search_res.count} of {search_res.total} - next {search_res.next()}",
    )

    print("\nVerify membership proofs\n\t", end="")
    for row in search_res.result.events:
        ok = audit.verify_membership_proof(search_res.result.root, row, False)
        print("." if ok else "x", end=" ")
    print("")

    print("Verify consistency proofs\n\t", end="")
    for row in search_res.result.events:
        ok = audit.verify_consistency_proof(
            search_res.result.published_roots, row, False
        )
        print("." if ok else "x", end=" ")
    print("")


if __name__ == "__main__":
    main()

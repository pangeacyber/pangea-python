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

    print("Search Data...")
    search_res = audit.search(
        query="message:test",
        sources=["ppi_3tAdYJUiyssGgJJf7B1SbYLpsdPo"],
        size=5,
        verify=False,
    )
    if search_res.success:
        print("Search Request ID:", search_res.request_id, "\n")
        print_page_results(search_res)

        # get next pages
        while True:
            last = search_res.next()
            if last is not None:
                print_page_results(audit.search(last, verify=False))
            else:
                break
    else:
        print("Search Failed:", search_res.code, search_res.status)


def print_page_results(search_res):
    print("\n--------------------------------------------------------------------\n")
    for row in search_res.result.events:
        print(
            f"{row.data.message}\t{row.data.created}\t{row.data.source}\t{row.data.actor}"
        )
    print(
        f"\nResults: {search_res.count} of {search_res.total} - next {search_res.next()}",
    )

    print("\nVerify membership proofs\n\t", end="")
    for row in search_res.result.events:
        ok = audit.verify_membership_proof(search_res.result.root, row, False)
        print("." if ok else "x", end="\t")
    print("")

    print("Verify consistency proofs\n\t", end="")
    for row in search_res.result.events:
        ok = audit.verify_consistency_proof(
            search_res.result.published_roots, row, False
        )
        print("." if ok else "x", end="\t")


if __name__ == "__main__":
    main()

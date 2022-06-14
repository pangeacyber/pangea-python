import os

from pangea.config import PangeaConfig
from pangea.services import Audit

token = os.getenv("PANGEA_TOKEN")
config = PangeaConfig(base_domain="dev.pangea.cloud", insecure=False)
audit = Audit(token=token, config=config)

data = {
		"action": "diego",
		"actor": "testing2",
		"message": "Hello",
        "status": "xxx",
		"new": "xxx",
        "old": "xxx",
        "target": "xxx"
}

def main():
    print("Log Data...")    
    log_response = audit.log(data)
    print(f"Log Request ID: {log_response.request_id}, Result: {log_response.result}")

    print("Search Data...")
    search_res = audit.search(query="message:prueba_cron", size=5, verify_proofs=True)

    if search_res.success:
        print("Search Request ID:", search_res.request_id, "\n")
        print_page_results(search_res)

        # get next pages
        while search_res.next():
            search_res = audit.search(**search_res.next(), verify_proofs = True)
            print_page_results(search_res)
    else:
        print("Search Failed:", search_res.code, search_res.status)


def print_page_results(search_res):
        print("\n--------------------------------------------------------------------\n")
        for row in search_res.result.audits:
            print(f"{row.data.message}\t{row.data.created}\t{row.data.source}\t{row.data.actor}")        
        print(
            f"\nResults: {search_res.count} of {search_res.total} - next {search_res.next()}",
        )

        print("\nVerify membership proofs\n\t", end="")
        for row in search_res.result.audits:
            ok = audit.verify_membership_proof(search_res.result.root, row, True)
            print("." if ok else "x", end="\t")
        print("")

        print("Verify consistency proofs\n\t", end="")
        for row in search_res.result.audits:
            ok = audit.verify_consistency_proof(row, True)
            print("." if ok else "x", end="\t")


if __name__ == "__main__":
    main()
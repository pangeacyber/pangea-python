import os
from urllib.parse import urlparse

import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import DomainIntel, UrlIntel

token = os.getenv("PANGEA_INTEL_TOKEN")
domain = os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)
url_intel = UrlIntel(token, config=config)
domain_intel = DomainIntel(token, config=config)
defanged_schemes = {"http": "hxxp", "https": "hxxps"}


def get_domain(url: str) -> str:
    o = urlparse(url)
    return o.hostname


def defang(url: str) -> str:
    o = urlparse(url)
    defang_scheme = defanged_schemes.pop(o.scheme, "xxxx")
    return o._replace(scheme=defang_scheme).geturl()


def main():
    print("Checking URL...")
    url = "http://113.235.101.11:54384"

    try:
        response = url_intel.reputation(url=url, provider="crowdstrike", verbose=True, raw=True)
        if response.result.data.verdict == "malicious":
            defanged_url = defang(url)
            print("Defanged URL: ", defanged_url)
        else:
            domain = get_domain(url)
            response = domain_intel.reputation(domain=domain, provider="domaintools", verbose=True, raw=True)
            if response.result.data.verdict == "malicious":
                defanged_url = defang(url)
                print("Defanged URL: ", defanged_url)
            else:
                print(f"URL {url} should be secure")

    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")


if __name__ == "__main__":
    main()

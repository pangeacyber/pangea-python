# Defang malicious domains and URLs.

import asyncio
import os
from urllib.parse import urlparse

import pangea.exceptions as pe
from pangea.asyncio.services import DomainIntelAsync, UrlIntelAsync
from pangea.config import PangeaConfig

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
domain = os.getenv("PANGEA_DOMAIN")
assert domain
config = PangeaConfig(domain=domain)
url_intel = UrlIntelAsync(token, config=config)
domain_intel = DomainIntelAsync(token, config=config)
defanged_schemes = {"http": "hxxp", "https": "hxxps"}


def get_domain(url: str) -> str:
    o = urlparse(url)
    assert o.hostname
    return o.hostname


def defang(url: str) -> str:
    o = urlparse(url)
    defang_scheme = defanged_schemes.pop(o.scheme, "xxxx")
    return o._replace(scheme=defang_scheme).geturl()


async def main() -> None:
    print("Checking URL...")
    url = "http://113.235.101.11:54384"

    try:
        response = await url_intel.reputation(url=url, provider="crowdstrike", verbose=True, raw=True)
        assert response.result
        if response.result.data.verdict == "malicious":
            defanged_url = defang(url)
            print("Defanged URL: ", defanged_url)
        else:
            domain = get_domain(url)
            response = await domain_intel.reputation(domain=domain, provider="domaintools", verbose=True, raw=True)  # type: ignore[assignment]
            assert response.result
            if response.result.data.verdict == "malicious":
                defanged_url = defang(url)
                print("Defanged URL: ", defanged_url)
            else:
                print(f"URL {url} should be secure")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")
    finally:
        await url_intel.close()
        await domain_intel.close()


if __name__ == "__main__":
    asyncio.run(main())

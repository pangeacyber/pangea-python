import asyncio
import os

import pangea.exceptions as pe
from pangea.asyncio.services import IpIntelAsync
from pangea.config import PangeaConfig

token = os.getenv("PANGEA_INTEL_TOKEN")
assert token
url_template = os.getenv("PANGEA_URL_TEMPLATE")
assert url_template
config = PangeaConfig(base_url_template=url_template)
intel = IpIntelAsync(token, config=config)


async def main():
    print("Get IP's Domain...")

    try:
        response = await intel.get_domain(ip="24.235.114.61", provider="digitalelement", verbose=True, raw=True)
        print(f"IP's domain was {'' if response.result.data.domain_found is True else 'not '}found")
        if response.result.data.domain_found:
            print(f"IP's domain is: {response.result.data.domain}")
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        print(e)

    await intel.close()


if __name__ == "__main__":
    asyncio.run(main())

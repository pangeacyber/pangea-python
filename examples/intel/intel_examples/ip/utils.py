from typing import Dict

from pangea.services.intel import IPDomainData, IPGeolocateData, IPProxyData, IPVPNData


def print_ip_domain_data(ip: str, data: IPDomainData):
    print(f"\tIP {ip}: domain was {'' if data.domain_found is True else 'not '}found")
    if data.domain_found:
        print(f"\tDomain is: {data.domain}")


def print_ip_domain_bulk_data(data: Dict[str, IPDomainData]):
    for k, v in data.items():
        print_ip_domain_data(k, v)
        print("")


def print_ip_proxy_data(ip: str, data: IPProxyData):
    if data.is_proxy:
        print(f"\tIP {ip} is a proxy")
    else:
        print(f"\tIP {ip} is not a proxy")


def print_ip_proxy_bulk_data(data: Dict[str, IPProxyData]):
    for k, v in data.items():
        print_ip_proxy_data(k, v)


def print_ip_vpn_data(ip: str, data: IPVPNData):
    if data.is_vpn:
        print(f"\tIP {ip} is a VPN")
    else:
        print(f"\tIP {ip} is not a VPN")


def print_ip_vpn_bulk_data(data: Dict[str, IPVPNData]):
    for k, v in data.items():
        print_ip_vpn_data(k, v)


def print_ip_geolocate_data(ip: str, data: IPGeolocateData):
    print(f"\tIP: {ip}")
    print(f"\t\tCountry: {data.country}")
    print(f"\t\tCity: {data.city}")
    print(f"\t\tLatitude: {data.latitude}")
    print(f"\t\tLongitude: {data.longitude}")
    print(f"\t\tPostal_code: {data.postal_code}")
    print(f"\t\tCountry_code: {data.country_code}")


def print_ip_geolocate_bulk_data(data: Dict[str, IPGeolocateData]):
    for k, v in data.items():
        print_ip_geolocate_data(k, v)

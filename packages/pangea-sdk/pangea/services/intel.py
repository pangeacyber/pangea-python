# Copyright 2022 Pangea Cyber Corporation
# Author: Pangea Cyber Corporation
import enum
import hashlib
from typing import Dict, List, Optional

from pangea.exceptions import PangeaException
from pangea.response import APIRequestModel, PangeaResponse, PangeaResponseResult

from .base import ServiceBase


class IntelCommonRequest(APIRequestModel):
    """
    Intel common request data

    provider (str, optional): Provider of the information. Default provider defined by the configuration.
    verbose (bool, optional): Echo back the parameters of the API in the response
    raw (bool, optional): Return additional details from the provider.
    """

    verbose: Optional[bool] = None
    raw: Optional[bool] = None
    provider: Optional[str] = None


class IntelCommonResult(PangeaResponseResult):
    """
    Intel common result data
    """

    parameters: Optional[Dict] = None
    raw_data: Optional[Dict] = None


class FileReputationRequest(IntelCommonRequest):
    """
    File reputation request data

    file_hash (str): Hash of the file to be looked up
    hash_type (str): Type of hash, can be "sha256", "sha" or "md5"
    """

    hash: str
    hash_type: str


class FileReputationData(PangeaResponseResult):
    """
    File reputation information
    """

    category: List[str]
    score: int
    verdict: str


class FileReputationResult(IntelCommonResult):
    """
    File reputation result information
    """

    data: FileReputationData


class IPCommonRequest(IntelCommonRequest):
    """
    IP common request data
    ip (str): IP address to search for reputation information
    """

    ip: str


class IPRepurationRequest(IPCommonRequest):
    """
    IP reputation request data

    """

    pass


class IPReputationData(PangeaResponseResult):
    """
    IP reputation information
    """

    category: List[str]
    score: int
    verdict: str


class IPReputationResult(IntelCommonResult):
    """
    IP reputation result
    """

    data: IPReputationData


class IPGeolocateRequest(IPCommonRequest):
    """
    IP geolocate request data
    """

    pass


class IPGeolocateData(PangeaResponseResult):
    """
    IP geolocate data
    """

    country: str
    city: str
    latitude: float
    longitude: float
    postal_code: str
    country_code: str


class IPGeolocateResult(IntelCommonResult):
    """
    IP geolocate result
    """

    data: IPGeolocateData


class IPDomainRequest(IPCommonRequest):
    """
    IP domain request data
    """

    pass


class IPDomainData(PangeaResponseResult):
    domain_found: bool
    domain: Optional[str] = None


class IPDomainResult(IntelCommonResult):
    """
    IP geolocate result
    """

    data: IPDomainData


class IPVPNRequest(IPCommonRequest):
    """
    IP VPN request data
    """

    pass


class IPVPNData(PangeaResponseResult):
    is_vpn: bool


class IPVPNResult(IntelCommonResult):
    """
    IP geolocate result
    """

    data: IPVPNData


class IPProxyRequest(IPCommonRequest):
    """
    IP VPN request data
    """

    pass


class IPProxyData(PangeaResponseResult):
    is_proxy: bool


class IPProxyResult(IntelCommonResult):
    """
    IP geolocate result
    """

    data: IPProxyData


class DomainCommonRequest(IntelCommonRequest):
    """
    Domain lookup request data

    domain (str): Domain address to be analyzed
    """

    domain: str


class DomainReputationRequest(DomainCommonRequest):
    """
    Domain reputation request data
    """

    pass


class DomainReputationData(PangeaResponseResult):
    """
    Domain Reputation information
    """

    category: List[str]
    score: int
    verdict: str


class DomainReputationResult(IntelCommonResult):
    """
    Domain reputation result
    """

    data: DomainReputationData


class DomainWhoIsRequest(DomainCommonRequest):
    """
    Domain whois request data
    """

    pass


class DomainWhoIsData(PangeaResponseResult):
    """
    Represents information about a domain.

    Attributes:
        domain_name (str): The domain name.
        domain_availability (str): The availability of the domain.
        created_date (str, optional): The date the domain was created.
        updated_date (str, optional): The date the domain was last updated.
        expires_date (str, optional): The date the domain expires.
        host_names (List[str], optional): The host names associated with the domain.
        ips (List[str], optional): The IP addresses associated with the domain.
        registrar_name (str, optional): The name of the registrar.
        contact_email (str, optional): The email address of the contact.
        estimated_domain_age (int, optional): The estimated age of the domain.
        registrant_organization (str, optional): The organization of the registrant.
        registrant_country (str, optional): The country of the registrant.
    """

    domain_name: str
    domain_availability: str
    created_date: Optional[str] = None
    updated_date: Optional[str] = None
    expires_date: Optional[str] = None
    host_names: Optional[List[str]] = None
    ips: Optional[List[str]] = None
    registrar_name: Optional[str] = None
    contact_email: Optional[str] = None
    estimated_domain_age: Optional[int] = None
    registrant_organization: Optional[str] = None
    registrant_country: Optional[str] = None


class DomainWhoIsResult(IntelCommonResult):
    """
    Domain whois result
    """

    data: DomainWhoIsData


class URLCommonRequest(IntelCommonRequest):
    """
    URL common request data

    url (str): URL address to be analyzed
    """

    url: str


class URLReputationRequest(URLCommonRequest):
    """
    URL reputation request data
    """

    pass


class URLReputationData(PangeaResponseResult):
    """
    URL reputation information
    """

    category: List[str]
    score: int
    verdict: str


class URLReputationResult(IntelCommonResult):
    """
    URL Reputation result
    """

    data: URLReputationData


class HashType(str, enum.Enum):
    SHA256 = "sha256"
    SHA1 = "sha1"
    SHA512 = "sha512"
    NTLM = "ntlm"

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


class FileIntel(ServiceBase):
    """File Intel service client

    Provides methods to interact with [Pangea File Intel Service](https://pangea.cloud/docs/api/file-intel)

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import FileIntel

        PANGEA_TOKEN = os.getenv("PANGEA_INTEL_TOKEN")

        file_intel_config = PangeaConfig(domain="aws.us.pangea.cloud")

        # Setup Pangea File Intel service
        file_intel = FileIntel(token=PANGEA_TOKEN, config=file_intel_config)
    """

    service_name = "file-intel"

    def hash_reputation(
        self,
        hash: str,
        hash_type: str,
        provider: Optional[str] = None,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
    ) -> PangeaResponse[FileReputationResult]:
        """
        Reputation check

        Retrieve hash-based file reputation from a provider, including an optional detailed report.

        Args:
            hash (str): The hash of the file to be looked up
            hash_type (str): One of "sha256", "sha", "md5"
            provider (str, optional): Use reputation data from these providers: "reversinglabs" or "crowdstrike"
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/file-intel).

        Examples:
            response = file_intel.hashReputation(hash="142b638c6a60b60c7f9928da4fb85a5a8e1422a9ffdc9ee49e17e56ccca9cf6e", hash_type="sha256", provider="reversinglabs")

        """
        input = FileReputationRequest(hash=hash, hash_type=hash_type, verbose=verbose, raw=raw, provider=provider)
        return self.request.post("v1/reputation", FileReputationResult, data=input.dict(exclude_none=True))

    def filepath_reputation(
        self,
        filepath: str,
        provider: Optional[str] = None,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
    ) -> PangeaResponse[FileReputationResult]:
        """
        Reputation, from filepath

        Retrieve hash-based file reputation from a provider, including an optional detailed report.
        This function take care of calculate filepath hash and make the request to service

        OperationId: file_intel_post_v1_reputation

        Args:
            filepath (str): The path to the file to be looked up
            provider (str, optional): Use reputation data from these providers: "reversinglabs" or "crowdstrike"
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/file-intel).

        Examples:
            response = file_intel.filepathReputation(
                filepath="./myfile.exe",
                provider="reversinglabs",
            )
        """

        data = open(filepath, "rb")
        hash = hashlib.sha256(data.read()).hexdigest()

        input = FileReputationRequest(hash=hash, hash_type="sha256", verbose=verbose, raw=raw, provider=provider)
        return self.request.post("v1/reputation", FileReputationResult, data=input.dict(exclude_none=True))


class DomainIntel(ServiceBase):
    """Domain Intel service client

    Provides methods to interact with [Pangea Domain Intel Service](https://pangea.cloud/docs/api/domain-intel)

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import DomainIntel

        PANGEA_TOKEN = os.getenv("PANGEA_INTEL_TOKEN")

        domain_intel_config = PangeaConfig(domain="aws.us.pangea.cloud")

        # Setup Pangea Domain Intel service
        domain_intel = DomainIntel(token=PANGEA_TOKEN, config=domain_intel_config)
    """

    service_name = "domain-intel"

    def reputation(
        self, domain: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[DomainReputationResult]:
        """
        Reputation

        Retrieve reputation for a domain from a provider, including an optional detailed report.

        OperationId: domain_intel_post_v1_reputation

        Args:
            domain (str): The domain to be looked up
            provider (str, optional): Use reputation data from these providers: "domaintools" or "crowdstrike"
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/domain-intel).

        Examples:
            response = domain_intel.reputation(
                domain="737updatesboeing.com",
                provider="domaintools",
            )
        """
        input = DomainReputationRequest(domain=domain, verbose=verbose, provider=provider, raw=raw)
        return self.request.post("v1/reputation", DomainReputationResult, data=input.dict(exclude_none=True))

    def who_is(
        self, domain: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[DomainWhoIsResult]:
        """
        WhoIs

        Retrieve who is for a domain from a provider, including an optional detailed report.

        OperationId: domain_intel_post_v1_whois

        Args:
            domain (str): The domain to query.
            provider (str, optional): Use whois data from this provider "whoisxml"
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](https://pangea.cloud/docs/api/domain-intel).

        Examples:
            response = domain_intel.who_is(
                domain="google.com",
                provider="whoisxml",
            )
        """
        input = DomainWhoIsRequest(domain=domain, verbose=verbose, provider=provider, raw=raw)
        return self.request.post("v1/whois", DomainWhoIsResult, data=input.dict(exclude_none=True))


class IpIntel(ServiceBase):
    """IP Intel service client

    Provides methods to interact with [Pangea IP Intel Service](/docs/api/ip-intel)

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import IpIntel

        PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")

        ip_intel_config = PangeaConfig(domain="pangea.cloud")

        # Setup Pangea IP Intel service
        ip_intel = IpIntel(token=PANGEA_TOKEN, config=ip_intel_config)
    """

    service_name = "ip-intel"

    def reputation(
        self, ip: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[IPReputationResult]:
        """
        Reputation

        Retrieve a reputation score for an IP address from a provider, including an optional detailed report.

        OperationId: ip_intel_post_v1_reputation

        Args:
            ip (str): The IP to be looked up
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider
            provider (str, optional): Use reputation data from this provider: "crowdstrike"

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/ip-intel)

        Examples:
            response = ip_intel.reputation(
                ip="93.231.182.110",
                provider="crowdstrike",
            )
        """
        input = IPRepurationRequest(ip=ip, verbose=verbose, raw=raw, provider=provider)
        return self.request.post("v1/reputation", IPReputationResult, data=input.dict(exclude_none=True))

    def geolocate(
        self, ip: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[IPGeolocateResult]:
        """
        Geolocate

        Retrieve information about the location of an IP address.

        OperationId: ip_intel_post_v1_geolocate

        Args:
            ip (str): IP address to be geolocated
            provider (str, optional): Use geolocation data from this provider ("digitalelement"). Default provider defined by the configuration.
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the IP information is in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/ip-intel)

        Examples:
            response = ip_intel.geolocate(
                ip="93.231.182.110",
                provider="digitalelement",
            )
        """
        input = IPGeolocateRequest(ip=ip, verbose=verbose, raw=raw, provider=provider)
        return self.request.post("v1/geolocate", IPGeolocateResult, data=input.dict(exclude_none=True))

    def get_domain(
        self, ip: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[IPDomainResult]:
        """
        Domain

        Retrieve the domain name associated with an IP address.

        OperationId: ip_intel_post_v1_domain

        Args:
            ip (str): The IP to be looked up
            provider (str, optional): Use geolocation data from this provider ("digitalelement"). Default provider defined by the configuration.
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the IP information is in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/ip-intel)

        Examples:
            response = ip_intel.get_domain(
                ip="93.231.182.110",
                provider="digitalelement",
            )
        """
        input = IPDomainRequest(ip=ip, verbose=verbose, raw=raw, provider=provider)
        return self.request.post("v1/domain", IPDomainResult, data=input.dict(exclude_none=True))

    def is_vpn(
        self, ip: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[IPVPNResult]:
        """
        VPN

        Determine if an IP address is provided by a VPN service.

        OperationId: ip_intel_post_v1_vpn

        Args:
            ip (str): The IP to be looked up
            provider (str, optional): Use geolocation data from this provider ("digitalelement"). Default provider defined by the configuration.
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the IP information is in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/ip-intel)

        Examples:
            response = ip_intel.is_vpn(
                ip="93.231.182.110",
                provider="digitalelement",
            )
        """
        input = IPVPNRequest(ip=ip, verbose=verbose, raw=raw, provider=provider)
        return self.request.post("v1/vpn", IPVPNResult, data=input.dict(exclude_none=True))

    def is_proxy(
        self, ip: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[IPProxyResult]:
        """
        Proxy

        Determine if an IP address is provided by a proxy service.

        OperationId: ip_intel_post_v1_proxy

        Args:
            ip (str): The IP to be looked up
            provider (str, optional): Use geolocation data from this provider ("digitalelement"). Default provider defined by the configuration.
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the IP information is in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/ip-intel)

        Examples:
            response = ip_intel.is_proxy(
                ip="93.231.182.110",
                provider="digitalelement",
            )
        """
        input = IPProxyRequest(ip=ip, verbose=verbose, raw=raw, provider=provider)
        return self.request.post("v1/proxy", IPProxyResult, data=input.dict(exclude_none=True))


class UrlIntel(ServiceBase):
    """URL Intel service client.

    Provides methods to interact with [Pangea URL Intel Service](/docs/api/url-intel)

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import UrlIntel

        PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")

        url_intel_config = PangeaConfig(domain="pangea.cloud")

        # Setup Pangea URL Intel service
        url_intel = UrlIntel(token=PANGEA_TOKEN, config=url_intel_config)
    """

    service_name = "url-intel"

    def reputation(
        self, url: str, verbose: Optional[bool] = None, raw: Optional[bool] = None, provider: Optional[str] = None
    ) -> PangeaResponse[URLReputationResult]:
        """
        Reputation

        Retrieve URL address reputation from a provider.

        OperationId: url_intel_post_v1_reputation

        Args:
            url (str): The URL to be looked up
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider
            provider (str, optional): Use reputation data from this provider: "crowdstrike"

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/url-intel)

        Examples:
            response = url_intel.reputation(
                url="http://113.235.101.11:54384",
                provider="crowdstrike",
            )
        """

        input = URLReputationRequest(url=url, provider=provider, verbose=verbose, raw=raw)
        return self.request.post("v1/reputation", URLReputationResult, data=input.dict(exclude_none=True))


class UserBreachedRequest(IntelCommonRequest):
    """
    User breached common request data

    email (str): An email address to search for
    username (str): An username to search for
    ip (str): An ip to search for
    phone_number (str): A phone number to search for. minLength: 7, maxLength: 15.
    start (str): Earliest date for search
    end (str): Latest date for search
    """

    email: Optional[str] = None
    username: Optional[str] = None
    ip: Optional[str] = None
    phone_number: Optional[str] = None
    start: Optional[str] = None
    end: Optional[str] = None


class UserBreachedCommonData(PangeaResponseResult):
    """
    User breached common information
    """

    found_in_breach: bool
    breach_count: int


class UserBreachedData(UserBreachedCommonData):
    """
    User breached information
    """

    pass


class UserBreachedResult(IntelCommonResult):
    """
    User breached result
    """

    data: UserBreachedData


class UserPasswordBreachedRequest(IntelCommonRequest):
    """
    User password breached common request data

    hash_type (str): Hash type to be looked up
    hash_prefix (str): The prefix of the hash to be looked up.
    """

    hash_type: str
    hash_prefix: str


class UserPasswordBreachedData(UserBreachedCommonData):
    """
    User password breached information
    """

    pass


class UserPasswordBreachedResult(IntelCommonResult):
    """
    User password breached result
    """

    data: UserPasswordBreachedData


class UserIntel(ServiceBase):
    """User Intel service client.

    Provides methods to interact with [Pangea User Intel Service](/docs/api/user-intel)

    The following information is needed:
        PANGEA_TOKEN - service token which can be found on the Pangea User
            Console at [https://console.pangea.cloud/project/tokens](https://console.pangea.cloud/project/tokens)

    Examples:
        import os

        # Pangea SDK
        from pangea.config import PangeaConfig
        from pangea.services import UserIntel

        PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")

        user_intel_config = PangeaConfig(domain="pangea.cloud")

        # Setup Pangea User Intel service
        user_intel = UserIntel(token=PANGEA_TOKEN, config=user_intel_config)
    """

    service_name = "user-intel"

    def user_breached(
        self,
        email: Optional[str] = None,
        username: Optional[str] = None,
        ip: Optional[str] = None,
        phone_number: Optional[str] = None,
        start: Optional[str] = None,
        end: Optional[str] = None,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = None,
        provider: Optional[str] = None,
    ) -> PangeaResponse[UserBreachedResult]:
        """
        Look up breached users

        Find out if an email address, username, phone number, or IP address was exposed in a security breach.

        OperationId: user_intel_post_v1_user_breached

        Args:
            email (str): An email address to search for
            username (str): An username to search for
            ip (str): An ip to search for
            phone_number (str): A phone number to search for. minLength: 7, maxLength: 15.
            start (str): Earliest date for search
            end (str): Latest date for search
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider
            provider (str, optional): Use reputation data from this provider: "crowdstrike"

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/user-intel)

        Examples:
            response = user_intel.user_breached(
                phone_number="8005550123",
                provider="spycloud",
                verbose=True,
                raw=True,
            )
        """

        input = UserBreachedRequest(
            email=email,
            phone_number=phone_number,
            username=username,
            ip=ip,
            provider=provider,
            start=start,
            end=end,
            verbose=verbose,
            raw=raw,
        )
        return self.request.post("v1/user/breached", UserBreachedResult, data=input.dict(exclude_none=True))

    def password_breached(
        self,
        hash_type: HashType,
        hash_prefix: str,
        verbose: Optional[bool] = None,
        raw: Optional[bool] = True,
        provider: Optional[str] = None,
    ) -> PangeaResponse[UserPasswordBreachedResult]:
        """
        Look up breached passwords

        Find out if a password has been exposed in security breaches by providing a 5 character prefix of the password hash.

        OperationId: user_intel_post_v1_password_breached

        Args:
            hash_type (str): Hash type to be looked up
            hash_prefix (str): The prefix of the hash to be looked up.
            verbose (bool, optional): Echo the API parameters in the response
            raw (bool, optional): Include raw data from this provider
            provider (str, optional): Use reputation data from this provider: "crowdstrike"

        Raises:
            PangeaAPIException: If an API Error happens

        Returns:
            A PangeaResponse where the sanctioned source(s) are in the
                response.result field.  Available response fields can be found in our [API documentation](/docs/api/user-intel)

        Examples:
            response = user_intel.password_breached(
                hash_prefix="5baa6",
                hash_type=HashType.SHA256,
                provider="spycloud",
            )
        """

        input = UserPasswordBreachedRequest(
            hash_type=hash_type, hash_prefix=hash_prefix, provider=provider, verbose=verbose, raw=raw
        )
        return self.request.post("v1/password/breached", UserPasswordBreachedResult, data=input.dict(exclude_none=True))

    class PasswordStatus(enum.Enum):
        BREACHED = 0
        UNBREACHED = 1
        INCONCLUSIVE = 2

    @staticmethod
    def is_password_breached(response: PangeaResponse[UserBreachedResult], hash: str) -> PasswordStatus:
        if response.result.raw_data is None:
            raise PangeaException("Need raw data to check if hash is breached. Send request with raw=true")

        hash_data = response.result.raw_data.pop(hash, None)
        if hash_data is not None:
            # If hash is present in raw data, it's because it was breached
            return UserIntel.PasswordStatus.BREACHED
        else:
            # If it's not present, should check if I have all breached hash
            # Server will return a maximum of 1000 hash, so if breached count is greater than that,
            # I can't conclude is password is or is not breached
            if len(response.result.raw_data.keys()) >= 1000:
                return UserIntel.PasswordStatus.INCONCLUSIVE
            else:
                return UserIntel.PasswordStatus.UNBREACHED

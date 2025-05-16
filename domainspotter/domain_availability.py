import logging
import socket

import aiodns
from async_lru import alru_cache
from pydantic import BaseModel

log = logging.getLogger(__name__)


class DomainAvailabilityResult(BaseModel):
    domain: str
    is_available: bool
    error: str | None = None


class DomainAvailability:
    def __init__(self):
        """Initialize the domain availability checker with caching."""
        self._resolver = None

    @property
    def resolver(self):
        if not self._resolver:
            self._resolver = aiodns.DNSResolver()
        return self._resolver

    @alru_cache(maxsize=128)
    async def get_ns(self, domain: str, resolver: aiodns.DNSResolver | None = None) -> list[str]:
        """Get nameservers for a domain with caching."""
        resolver = resolver or self.resolver
        try:
            return [r.host for r in await resolver.query(domain, "NS")]
        except Exception:
            return []

    @alru_cache(maxsize=256)
    async def resolve_ip(
        self, hostname: str, resolver: aiodns.DNSResolver | None = None
    ) -> list[str]:
        """Resolve hostname to IP addresses with caching."""
        resolver = resolver or self.resolver
        try:
            res = await resolver.gethostbyname(hostname, socket.AF_INET)
            return res.addresses
        except Exception:
            return []

    async def authoritative_ns_lookup(self, domain: str) -> list[str] | str:
        """Perform recursive DNS lookup to find authoritative nameservers."""
        tld_parts = domain.split(".")[-2:] if domain.endswith(".co.uk") else [domain.split(".")[-1]]
        tld = ".".join(tld_parts) + "."

        tld_ns_names = await self.get_ns(tld)
        if not tld_ns_names:
            return "TLD NS resolution failed"

        tld_ns_ips: list[str] = []
        for ns in tld_ns_names:
            tld_ns_ips.extend(await self.resolve_ip(ns))

        if not tld_ns_ips:
            return "TLD NS IP resolution failed"

        auth_resolver = aiodns.DNSResolver(nameservers=tld_ns_ips)
        return await self.get_ns(domain, resolver=auth_resolver)

    async def check_domain(self, domain: str) -> DomainAvailabilityResult:
        """Check if a domain is available using authoritative nameserver lookup.

        Args:
            domain: The domain to check (e.g. "example.com")

        Returns:
            DomainAvailabilityResult with availability status
        """
        try:
            # First try direct NS lookup
            ns_records = await self.get_ns(domain)
            if ns_records:
                return DomainAvailabilityResult(domain=domain, is_available=False, error=None)

            # If no direct NS records, try authoritative lookup
            auth_ns = await self.authoritative_ns_lookup(domain)
            if isinstance(auth_ns, list) and auth_ns:
                return DomainAvailabilityResult(domain=domain, is_available=False, error=None)

            # If we get here, domain appears to be available
            return DomainAvailabilityResult(domain=domain, is_available=True, error=None)

        except aiodns.error.DNSError as e:
            # If we get NXDOMAIN or no records, domain might be available
            if e.args[0] in (3, 4):  # NXDOMAIN or no records
                return DomainAvailabilityResult(domain=domain, is_available=True, error=None)
            # Other DNS errors mean we can't determine availability
            return DomainAvailabilityResult(domain=domain, is_available=False, error=str(e))
        except Exception as e:
            log.error(f"Unexpected error checking domain {domain}: {e}")
            return DomainAvailabilityResult(domain=domain, is_available=False, error=str(e))

    async def check_domains(self, domains: list[str]) -> list[DomainAvailabilityResult]:
        """Check multiple domains in parallel.

        Args:
            domains: List of domains to check

        Returns:
            List of DomainAvailabilityResult objects
        """
        import asyncio

        tasks = [self.check_domain(domain) for domain in domains]
        return await asyncio.gather(*tasks)

import asyncio
import logging
import random
import socket

import aiodns
from async_lru import alru_cache
from pydantic import BaseModel

log = logging.getLogger(__name__)


class DomainAvailabilityResult(BaseModel):
    domain: str
    is_available: bool
    error: str | None = None


# these all have to be global variables because of the alru_cache
_resolver = None


def resolver():
    global _resolver
    if not _resolver:
        _resolver = aiodns.DNSResolver()
    return _resolver


@alru_cache(maxsize=256)
async def get_tld_ns(tld: str) -> list[str]:
    """Get nameservers for a TLD."""
    return [r.host for r in await resolver().query(tld, "NS")]


@alru_cache(maxsize=256)
async def resolve_ip(hostname: str) -> str | None:
    """Resolve hostname to IP addresses with caching."""
    try:
        res = await resolver().gethostbyname(hostname, socket.AF_INET)
        log.info(f"Resolved {hostname} to {res.addresses}")
        return random.choice(res.addresses)
    except Exception:
        return None


async def get_ns(domain: str, resolver: aiodns.DNSResolver) -> list[str]:
    """Get nameservers for a domain with caching."""
    return [r.host for r in await resolver.query(domain + ".", "NS")]


@alru_cache(maxsize=128)
async def get_resolver_for_tld(tld: str) -> aiodns.DNSResolver:
    """Get a resolver for a TLD with caching."""
    tld_ns_names = await get_tld_ns(tld)
    tld_ns_ips = await asyncio.gather(*[resolve_ip(ns) for ns in tld_ns_names])
    return aiodns.DNSResolver(nameservers=tld_ns_ips)


class DomainAvailability:
    def __init__(self):
        global _resolver
        _resolver = None
        # clear all caches
        get_tld_ns.cache_clear()
        resolve_ip.cache_clear()
        get_resolver_for_tld.cache_clear()

    async def authoritative_availability(self, domain: str) -> bool:
        """Perform recursive DNS lookup to find authoritative nameservers."""
        log.info(f"Performing authoritative NS lookup for {domain}")
        tld = ".".join(domain.split(".")[-1:]) + "."
        resolver = await get_resolver_for_tld(tld)
        try:
            await resolver.query(domain + ".", "NS")
            return True
        except aiodns.error.DNSError as e:
            if e.args[0] == 1:  # no records means it's NOT available
                # this is because aiodns doesn't support authority queries properly
                return False
            if e.args[0] in (3, 4):  # NXDOMAIN or no records means it's available
                return True
            log.error(f"DNS error performing authoritative NS lookup for {domain}: {e}")
            return False
        except Exception as e:
            log.error(f"Unexpected error performing authoritative NS lookup for {domain}: {e}")
            return False

    async def check_domain(self, domain: str) -> DomainAvailabilityResult:
        """Check if a domain is available using authoritative nameserver lookup.

        Args:
            domain: The domain to check (e.g. "example.com")

        Returns:
            DomainAvailabilityResult with availability status
        """
        try:
            is_available = await self.authoritative_availability(domain)
            return DomainAvailabilityResult(domain=domain, is_available=is_available)
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

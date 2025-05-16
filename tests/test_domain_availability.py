import pytest

from domainspotter.domain_availability import DomainAvailability, DomainAvailabilityResult


@pytest.fixture
def availability_checker():
    return DomainAvailability()


@pytest.mark.asyncio
async def test_check_domains(availability_checker):
    # Test with real domains
    domains = [
        "example.com",  # Should be taken
        "google.com",  # Should be taken
        "df08hweg08bggwe0h.com",  # Should be available
    ]

    results = await availability_checker.check_domains(domains)

    # Verify we got results for all domains
    assert len(results) == 3

    # Verify example.com is taken
    example_result = next(r for r in results if r.domain == "example.com")
    assert not example_result.is_available
    assert example_result.error is None

    # Verify google.com is taken
    google_result = next(r for r in results if r.domain == "google.com")
    assert not google_result.is_available
    assert google_result.error is None

    # Verify random domain is available
    random_result = next(r for r in results if r.domain == "df08hweg08bggwe0h.com")
    assert random_result.is_available
    assert random_result.error is None


@pytest.mark.asyncio
async def test_check_domain_single(availability_checker):
    # Test single domain check
    result = await availability_checker.check_domain("example.com")
    assert isinstance(result, DomainAvailabilityResult)
    assert result.domain == "example.com"
    assert not result.is_available
    assert result.error is None

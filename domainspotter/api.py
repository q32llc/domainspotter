import logging
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter
from openai import AsyncOpenAI

from domainspotter.domain_availability import DomainAvailability

from .domain_search import DomainSearch
from .models import DomainRequest, DomainsWithAvailability, Idea, QuestionRequest, QuestionResponse

availability = DomainAvailability()
log = logging.getLogger(__name__)

router = APIRouter(prefix="/api")


@router.post("/questions", response_model=QuestionResponse)
async def get_questions(request: QuestionRequest) -> QuestionResponse:
    """Get questions for a domain idea"""
    domain_search = DomainSearch(AsyncOpenAI())
    idea = Idea(
        id=uuid4(),
        name=request.name,
        state={"description": request.description},
        created_at=datetime.now(tz=timezone.utc),
    )

    result = await domain_search.get_questions(idea)
    return QuestionResponse(questions=result.state["questions"])


@router.post("/domains", response_model=DomainsWithAvailability)
async def get_domains(request: DomainRequest) -> DomainsWithAvailability:
    """Get domain suggestions for a domain idea"""
    domain_search = DomainSearch(AsyncOpenAI())
    idea = Idea(
        id=uuid4(),
        name=request.name,
        state={
            "description": request.description,
            "questions": request.answered_questions,
        },
        created_at=datetime.now(tz=timezone.utc),
    )

    doms = await domain_search.get_domain_names(idea)
    ret = DomainsWithAvailability.from_domains(doms)

    all_domains = [d.domain for d in ret.domains]
    results = await availability.check_domains(all_domains)

    map_results = {result.domain: result.is_available for result in results}

    for domain in ret.domains:
        domain.is_available = map_results[domain.domain]

    ret.domains = [d for d in ret.domains if d.is_available]

    return ret

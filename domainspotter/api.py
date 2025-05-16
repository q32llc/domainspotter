import logging
from uuid import uuid4
from datetime import datetime, timezone

from fastapi import APIRouter
from openai import AsyncOpenAI

from .domain_search import DomainSearch
from .models import (
    Domains,
    Idea,
    QuestionRequest,
    QuestionResponse,
    DomainRequest,
)
from domainspotter.domain_availability import DomainAvailability

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

@router.post("/domains", response_model=Domains)
async def get_domains(request: DomainRequest) -> Domains:
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
    
    result = await domain_search.get_domain_names(idea)

    for domain in result.domains:
        domain.is_available = await availability.check_domain(domain.domain)

    return result
from datetime import datetime, timezone
import pytest
from unittest.mock import AsyncMock, MagicMock, Mock, patch
from uuid import UUID
from openai import AsyncOpenAI
from openai.types.chat import ChatCompletion
from pydantic import BaseModel

from domainspotter.domain_search import DomainSearch
from domainspotter.models import Idea, DomainEntry, Domains

# Global test data
SAMPLE_IDEA = Idea(
    id=UUID("12345678-1234-5678-1234-567812345678"),
    name="Test Idea",
    state={"description": "A test domain idea"},
    created_at=datetime.now(tz=timezone.utc)
)

@pytest.fixture
def mock_openai():
    with patch('domainspotter.domain_search.AsyncOpenAI') as mock:
        client = MagicMock()
        client.beta.chat.completions.parse = AsyncMock()
        mock.return_value = client
        yield client

@pytest.fixture
def domain_search(mock_openai):
    return DomainSearch(mock_openai)

@pytest.mark.asyncio
async def test_get_questions_success(domain_search, mock_openai):
    # Mock the OpenAI response
    mock_response = MagicMock()
    mock_response.choices = [
        MagicMock(
            message=MagicMock(
                parsed=MagicMock(questions=["What is the target audience?", "Should it be .com only?"])
            )
        )
    ]
    mock_openai.beta.chat.completions.parse.return_value = mock_response
    
    result = await domain_search.get_questions(SAMPLE_IDEA)

    # Verify OpenAI was called with correct parameters
    mock_openai.beta.chat.completions.parse.assert_called_once()
    call_args = mock_openai.beta.chat.completions.parse.call_args
    assert call_args[1]["model"] == "gpt-4.1-mini"
    assert len(call_args[1]["messages"]) == 2
    assert call_args[1]["messages"][0]["role"] == "system"
    assert call_args[1]["messages"][1]["role"] == "user"

    assert result == SAMPLE_IDEA

@pytest.mark.asyncio
async def test_get_domain_names_success(domain_search, mock_openai):
    # Mock the OpenAI response
    mock_response = MagicMock()
    mock_response.choices = [
        MagicMock(
            message=MagicMock(
                parsed=Domains(
                    domains=[
                        DomainEntry(domain="testidea.com", reason="Simple and memorable domain name"),
                        DomainEntry(domain="testidea.io", reason="Modern TLD for tech companies"),
                        DomainEntry(domain="testidea.ai", reason="AI-focused TLD for innovative businesses")
                    ]
                )
            )
        )
    ]
    mock_openai.beta.chat.completions.parse.return_value = mock_response
    
    result = await domain_search.get_domain_names(SAMPLE_IDEA)

    # Verify OpenAI was called with correct parameters
    mock_openai.beta.chat.completions.parse.assert_called_once()
    call_args = mock_openai.beta.chat.completions.parse.call_args
    assert call_args[1]["model"] == "gpt-4.1-mini"
    assert len(call_args[1]["messages"]) == 2
    assert call_args[1]["messages"][0]["role"] == "system"
    assert call_args[1]["messages"][1]["role"] == "user"

    assert result.domains[0].domain == "testidea.com"


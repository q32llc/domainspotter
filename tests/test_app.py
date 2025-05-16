from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from domainspotter.app import app
from domainspotter.models import DomainEntry, Domains

client = TestClient(app)


@pytest.fixture
def mock_openai():
    with patch("domainspotter.api.AsyncOpenAI") as mock:
        client = MagicMock()
        client.beta.chat.completions.parse = AsyncMock()
        mock.return_value = client
        yield client


def test_get_questions(mock_openai):
    # Mock the OpenAI response
    mock_response = MagicMock()
    mock_response.choices = [
        MagicMock(
            message=MagicMock(
                parsed=MagicMock(
                    questions=["What is the target audience?", "Should it be .com only?"]
                )
            )
        )
    ]
    mock_openai.beta.chat.completions.parse.return_value = mock_response

    response = client.post(
        "/api/questions", json={"name": "Test App", "description": "A new social media platform"}
    )

    assert response.status_code == 200
    data = response.json()
    assert "questions" in data
    assert len(data["questions"]) == 2
    assert data["questions"][0] == "What is the target audience?"
    assert data["questions"][1] == "Should it be .com only?"


def test_get_domains(mock_openai):
    # Mock the OpenAI response
    mock_response = MagicMock()
    mock_response.choices = [
        MagicMock(
            message=MagicMock(
                parsed=Domains(
                    domains=[
                        DomainEntry(
                            domain="testapp.com", reason="Simple and memorable domain name"
                        ),
                        DomainEntry(domain="testapp.io", reason="Modern TLD for tech companies"),
                        DomainEntry(domain="availablerhf98b.io", reason="Available domain name"),
                    ]
                )
            )
        )
    ]
    mock_openai.beta.chat.completions.parse.return_value = mock_response

    response = client.post(
        "/api/domains",
        json={
            "name": "Test App",
            "description": "A new social media platform",
            "answered_questions": [
                {"question": "What is the target audience?", "answer": "Young professionals"},
                {"question": "Should it be .com only?", "answer": "No, any TLD is fine"},
            ],
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "domains" in data
    assert len(data["domains"]) == 3
    assert data["domains"][0]["domain"] == "testapp.com"
    assert data["domains"][0]["reason"] == "Simple and memorable domain name"
    assert data["domains"][0]["is_available"] is False
    assert data["domains"][1]["domain"] == "testapp.io"
    assert data["domains"][1]["reason"] == "Modern TLD for tech companies"
    assert data["domains"][1]["is_available"] is False
    assert data["domains"][2]["domain"] == "availablerhf98b.io"
    assert data["domains"][2]["reason"] == "Available domain name"
    assert data["domains"][2]["is_available"] is True

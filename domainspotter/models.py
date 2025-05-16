from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class User(BaseModel):
    """Represents a user"""

    id: UUID = Field(..., description="Unique identifier for the user")
    username: str | None = Field(None, description="Username of the user")
    email: str | None = Field(None, description="Email of the user")
    phone_number: str | None = Field(None, description="Phone number of the user")
    is_admin: bool = Field(False, description="Whether the user is an admin")
    created_at: datetime = Field(..., description="Date and time the user was created")
    removed_at: datetime | None = Field(None, description="Date and time the user was removed")
    org_id: int | None = Field(None, description="Organization ID of the user")
    state: dict[str, Any] = Field(default_factory=dict, description="State of the user")

    # accept oauth tokens from linkedin and github
    linkedin_id: str | None = Field(None, description="LinkedIn user ID of the user")
    github_id: str | None = Field(None, description="GitHub user ID of the user")


class UserWithPass(User):
    """User model that includes password hash - only for authentication purposes"""

    passhash: str = Field(..., description="Password hash of the user")


class Idea(BaseModel):
    id: UUID
    name: str
    state: dict[str, Any]
    created_at: datetime


class Lead(BaseModel):
    """Represents a lead from the website"""

    id: UUID = Field(..., description="Unique identifier for the lead")
    email: str = Field(..., description="Email address of the lead")
    name: str | None = Field(None, description="Name of the lead")
    phone: str | None = Field(None, description="Phone number of the lead")
    status: str = Field("new", description="Current status of the lead")
    source: str = Field("website", description="Source of the lead")
    metadata: dict[str, Any] | None = Field(None, description="Additional lead metadata")
    created_at: datetime = Field(..., description="When the lead was created")
    updated_at: datetime = Field(..., description="When the lead was last updated")


class IdeaCreate(BaseModel):
    """Request model for creating an idea"""

    name: str
    state: dict[str, Any] = {}


class LeadCreate(BaseModel):
    """Request model for creating a lead"""

    email: str
    name: str | None = None
    phone: str | None = None
    source: str = "website"
    metadata: dict[str, Any] | None = None


class QuestionRequest(BaseModel):
    name: str
    description: str


class QuestionResponse(BaseModel):
    questions: list[str]


class DomainRequest(BaseModel):
    name: str
    description: str
    answered_questions: list[dict[str, str]]


# used by the domain search and by the app reply format


class DomainEntry(BaseModel):
    """Base domain entry model used for AI responses"""

    domain: str = Field(..., description="The domain name with TLD")
    reason: str = Field(..., description="Explanation of why this domain is a good fit")


class DomainEntryWithAvailability(DomainEntry):
    """Extended domain entry model that includes availability status"""

    is_available: bool = Field(False, description="Whether the domain is available")


class Domains(BaseModel):
    """Base domains model used for AI responses"""

    domains: list[DomainEntry] = Field(..., description="A list of domain names with their reasons")


class DomainsWithAvailability(BaseModel):
    """Extended domains model that includes availability status"""

    domains: list[DomainEntryWithAvailability] = Field(
        ..., description="A list of domain names with their reasons and availability"
    )

    @classmethod
    def from_domains(cls, domains: Domains) -> "DomainsWithAvailability":
        """Convert a Domains model to DomainsWithAvailability"""
        return cls(
            domains=[
                DomainEntryWithAvailability(domain=d.domain, reason=d.reason, is_available=False)
                for d in domains.domains
            ]
        )

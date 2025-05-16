import uuid
from datetime import datetime, timezone

import pytest
from uuid import UUID

from domainspotter.db import AlreadyExistsError, get_passhash
from domainspotter.models import Idea, User, UserWithPass


@pytest.mark.asyncio
async def test_create_user(db):
    # Test creating a user with username and password
    user_id = await db.create_user(
        username="test@example.com",
        password="password123",
        email="test@example.com",
    )
    assert isinstance(user_id, UUID)

    # Test creating a user with github_id
    github_user_id = await db.create_user(
        github_id="12345",
        email="github@example.com",
    )
    assert isinstance(github_user_id, UUID)

    # Test duplicate username
    with pytest.raises(AlreadyExistsError):
        await db.create_user(
            username="test@example.com",
            password="password123",
        )


@pytest.mark.asyncio
async def test_get_user_for_auth(db):
    # Create a test user
    username = "auth@example.com"
    password = "password123"
    user_id = await db.create_user(
        username=username,
        password=password,
        email=username,
    )

    # Test getting user for auth
    user = await db.get_user_for_auth(username)
    assert isinstance(user, UserWithPass)
    assert user.username == username
    assert user.passhash == get_passhash(username, password)

    # Test non-existent user
    assert await db.get_user_for_auth("nonexistent@example.com") is None


@pytest.mark.asyncio
async def test_get_github_user(db):
    # Create a test user with github_id
    github_id = "12345"
    user_id = await db.create_user(
        github_id=github_id,
        email="github@example.com",
    )

    # Test getting user by github_id
    user = await db.get_github_user(github_id)
    assert isinstance(user, User)
    assert user.github_id == str(github_id)

    # Test non-existent github_id
    assert await db.get_github_user("99999") is None


@pytest.mark.asyncio
async def test_get_user_by_id(db):
    # Create a test user
    username = "id@example.com"
    user_id = await db.create_user(
        username=username,
        password="password123",
        email=username,
    )

    # Test getting user by ID
    user = await db.get_user_by_id(user_id)
    assert isinstance(user, User)
    assert user.username == username

    # Test non-existent user ID
    assert await db.get_user_by_id(uuid.uuid4()) is None


@pytest.mark.asyncio
async def test_create_and_get_idea(db):
    # Create a test user
    user_id = await db.create_user(
        username="idea@example.com",
        password="password123",
        email="idea@example.com",
    )

    # Test creating an idea
    idea_name = "Test Idea"
    idea_state = {"description": "Test description"}
    idea_id = await db.create_idea(user_id, idea_name, idea_state)
    assert isinstance(idea_id, UUID)

    # Test getting idea
    idea = await db.get_idea(idea_id, user_id)
    assert isinstance(idea, Idea)
    assert idea.name == idea_name
    assert idea.state == idea_state

    # Test getting ideas by user
    ideas = await db.get_ideas_by_user(user_id)
    assert len(ideas) == 1
    assert isinstance(ideas[0], Idea)
    assert ideas[0].name == idea_name

    # Test getting non-existent idea
    assert await db.get_idea(UUID("99999999-9999-9999-9999-999999999999"), user_id) is None

    # Test getting idea with wrong user
    wrong_user_id = await db.create_user(
        username="wrong@example.com",
        password="password123",
        email="wrong@example.com",
    )
    assert await db.get_idea(idea_id, wrong_user_id) is None


@pytest.mark.asyncio
async def test_delete_idea(db):
    # Create a test user
    user_id = await db.create_user(
        username="delete@example.com",
        password="password123",
        email="delete@example.com",
    )

    # Create an idea
    idea_id = await db.create_idea(user_id, "To Delete", {})

    # Test deleting idea
    assert await db.delete_idea(idea_id, user_id) is True

    # Verify idea is deleted
    assert await db.get_idea(idea_id, user_id) is None

    # Test deleting non-existent idea
    assert await db.delete_idea(UUID("99999999-9999-9999-9999-999999999999"), user_id) is False


@pytest.mark.asyncio
async def test_create_lead(db):
    # Test creating a lead
    lead_id = await db.create_lead(
        email="lead@example.com",
        name="Test Lead",
        phone="1234567890",
        source="test",
        metadata={"source": "test"},
    )
    assert isinstance(lead_id, UUID)

    # Test creating lead with minimal info
    minimal_lead_id = await db.create_lead(
        email="minimal@example.com",
    )
    assert isinstance(minimal_lead_id, UUID)

    # Test creating duplicate lead (should not raise error)
    duplicate_lead_id = await db.create_lead(
        email="lead@example.com",
    )
    assert isinstance(duplicate_lead_id, UUID) 
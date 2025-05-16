import base64
import hashlib
import json
import logging
import os
import uuid
from typing import Any
from uuid import UUID

import asyncpg
from openai import AsyncOpenAI

from .migrations import MIGRATIONS
from .models import Idea, User, UserWithPass

log = logging.getLogger(__name__)


class AlreadyExistsError(Exception):
    pass


DEFAULT_EXPIRE_TTL = 3600
DEFAULT_RETRY_TTL = 3600
DEFAULT_MAX_RETRIES = 3


class Database:
    def __init__(self):
        self.url = os.environ["DATABASE_URL"]
        self.pool: asyncpg.Pool | None = None
        self.openai = AsyncOpenAI()

    async def connect(self):
        """Connect to the database"""
        self.pool = await asyncpg.create_pool(self.url)

    async def close(self):
        """Close the database connection"""
        if self.pool:
            await self.pool.close()

    async def execute(self, query: str, *args: Any) -> None:
        """Execute a query"""
        if not self.pool:
            raise RuntimeError("Database not connected")
        async with self.pool.acquire() as conn:
            return await conn.execute(query, *args)

    async def fetch(self, query: str, *args: Any) -> list[dict[str, Any]]:
        """Fetch rows from a query"""
        if not self.pool:
            raise RuntimeError("Database not connected")
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query, *args)
            return [dict(row) for row in rows]

    async def fetchrow(self, query: str, *args: Any) -> dict[str, Any] | None:
        """Fetch a single row from a query"""
        if not self.pool:
            raise RuntimeError("Database not connected")
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(query, *args)
            return dict(row) if row else None

    async def fetchval(self, query: str, *args: Any) -> Any:
        """Fetch a single value from a query"""
        if not self.pool:
            raise RuntimeError("Database not connected")
        async with self.pool.acquire() as conn:
            return await conn.fetchval(query, *args)

    async def migrate(self):
        """Run all migrations"""
        for migration in MIGRATIONS:
            try:
                await migration(self)
            except (
                asyncpg.exceptions.DuplicateTableError,
                asyncpg.exceptions.DuplicateColumnError,
                asyncpg.exceptions.DuplicateObjectError,
            ):
                continue


def get_passhash(username: str, password: str) -> str:
    return base64.b64encode(hashlib.sha256(f"{username}:{password}".encode()).digest()).decode()


class DomainspotterDb(Database):
    async def create_user(
        self,
        email: str | None = None,
        phone_number: str | None = None,
        username: str | None = None,
        password: str | None = None,
        is_admin: bool = False,
        github_id: str | int | None = None,
        state: dict[str, Any] = {},
    ) -> UUID:
        """Create a new user"""
        # At least one identifier must be provided
        if not any([username, github_id]):
            raise ValueError("At least one of username or github_id must be provided")

        user_id = str(uuid.uuid4())
        passhash = get_passhash(username, password) if password else None

        query = """
        INSERT INTO users (id, email, phone_number, username, passhash, is_admin, github_id, state)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id
        """
        try:
            row = await self.fetchrow(
                query,
                user_id,
                email,
                phone_number,
                username,
                passhash,
                is_admin,
                str(github_id) if github_id else None,
                json.dumps(state),
            )
            if not row:
                raise RuntimeError("Failed to create user")
            return UUID(user_id)
        except asyncpg.UniqueViolationError as e:
            raise AlreadyExistsError("Username or email already in use") from e
        except Exception as e:
            raise e

    async def get_user_for_auth(self, username: str) -> UserWithPass | None:
        """Get a user by username for authentication"""
        query = """
        SELECT id, username, email, phone_number, passhash, is_admin, created_at, removed_at, state
        FROM users
        WHERE username = $1 AND removed_at IS NULL
        """
        row = await self.fetchrow(query, username)
        if not row:
            return None

        user_data = dict(row)
        user_data["state"] = json.loads(user_data["state"])
        return UserWithPass.model_validate(user_data)

    async def get_github_user(self, github_id: str | int) -> User | None:
        """Get a user by github_id"""
        query = """
        SELECT id, username, email, phone_number, is_admin, created_at, removed_at, state, github_id
        FROM users
        WHERE github_id = $1 AND removed_at IS NULL
        """
        row = await self.fetchrow(query, str(github_id))
        if not row:
            return None

        user_data = dict(row)
        user_data["state"] = json.loads(user_data["state"])
        return User.model_validate(user_data)

    async def get_user_by_id(self, user_id: UUID) -> User | None:
        """Get a user by ID"""
        query = """
        SELECT id, username, email, phone_number, is_admin, created_at, removed_at, state, github_id
        FROM users
        WHERE id = $1 AND removed_at IS NULL
        """
        row = await self.fetchrow(query, user_id)
        if not row:
            return None

        user_data = dict(row)
        user_data["state"] = json.loads(user_data["state"])
        return User.model_validate(user_data)

    async def create_idea(self, user_id: uuid.UUID, name: str, state: dict[str, Any] = {}) -> UUID:
        idea_id = await self.fetchval(
            "INSERT INTO ideas (id, user_id, name, state) VALUES ($1, $2, $3, $4) RETURNING id",
            str(uuid.uuid4()),
            user_id,
            name,
            json.dumps(state),
        )
        return idea_id

    async def get_ideas_by_user(self, user_id: uuid.UUID) -> list[Idea]:
        """Get all ideas for a user."""
        rows = await self.fetch(
            "SELECT id, name, state, created_at FROM ideas WHERE user_id = $1 ORDER BY created_at DESC",
            user_id,
        )
        for row in rows:
            row["state"] = json.loads(row["state"])
        return [Idea.model_validate(row) for row in rows]

    async def get_idea(self, idea_id: UUID, user_id: uuid.UUID) -> Idea | None:
        """Get a idea by ID and verify ownership."""
        row = await self.fetchrow(
            "SELECT id, name, state, created_at FROM ideas WHERE id = $1 AND user_id = $2",
            idea_id,
            user_id,
        )
        if row is None:
            return None
        row["state"] = json.loads(row["state"])
        return Idea.model_validate(row)

    async def delete_idea(self, idea_id: UUID, user_id: uuid.UUID) -> bool:
        """Delete a idea and all its items."""
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                result = await conn.execute(
                    "DELETE FROM ideas WHERE id = $1 AND user_id = $2", idea_id, user_id
                )
                return "DELETE 1" in result

    async def update_idea_state(
        self, idea_id: UUID, user_id: uuid.UUID, state: dict[str, Any]
    ) -> Idea | None:
        """Update an idea's state and return the updated idea, merging the new state with the existing state."""

        idea = await self.get_idea(idea_id, user_id)
        if not idea:
            return None

        idea.state = {**idea.state, **state}

        query = """
        UPDATE ideas
        SET state = $1
        WHERE id = $2 AND user_id = $3
        RETURNING id, name, state, created_at
        """
        row = await self.fetchrow(query, json.dumps(idea.state), idea_id, user_id)
        if not row:
            return None
        row["state"] = json.loads(row["state"])
        return Idea.model_validate(row)

    async def create_lead(
        self,
        email: str,
        name: str | None = None,
        phone: str | None = None,
        source: str = "website",
        metadata: dict[str, Any] | None = None,
    ) -> UUID:
        """Create a new lead"""
        lead_id = str(uuid.uuid4())

        query = """
        INSERT INTO leads (id, email, name, phone, source, metadata)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id
        """
        try:
            row = await self.fetchrow(
                query,
                lead_id,
                email,
                name,
                phone,
                source,
                json.dumps(metadata) if metadata else None,
            )
            if not row:
                raise RuntimeError("Failed to create lead")
            return UUID(lead_id)
        except asyncpg.UniqueViolationError as e:
            raise AlreadyExistsError("Email already in use") from e
        except Exception as e:
            raise e

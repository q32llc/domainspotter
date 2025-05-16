#!/usr/bin/env python3

import logging
import os
import time
import uuid
from collections.abc import AsyncGenerator

import asyncpg
import httpx
import pytest
from asgi_lifespan import LifespanManager
from dotenv import load_dotenv

from domainspotter.db import DomainspotterDb, get_passhash

load_dotenv()

os.environ["OPENAI_API_KEY"] = os.environ.get("TEST_OPENAI_API_KEY", "fake-key")
os.environ["JWT_SECRET_KEY"] = os.environ.get("TEST_JWT_SECRET_KEY", "fake-key")

# has to be imported after the env vars are set
from domainspotter.app import app, hash_auth_request  # noqa: E402

log = logging.getLogger(__name__)

# Generate a unique test database name
tmp_db_name = f"domainspotter_test_{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="session")
async def tmp_db():
    sys_url = "postgresql://postgres:postgres@localhost:5432"

    # Connect to default postgres to create test db
    sys_conn = await asyncpg.connect(
        dsn=sys_url,
        database="postgres",
    )

    try:
        # Drop test database if it exists
        await sys_conn.execute(f"DROP DATABASE IF EXISTS {tmp_db_name}")
        # Create fresh test database
        await sys_conn.execute(f"CREATE DATABASE {tmp_db_name}")
    finally:
        await sys_conn.close()

    # Parse and modify DATABASE_URL to use test database
    os.environ["DATABASE_URL"] = sys_url + "/" + tmp_db_name

    log.info("using tmp db %s", os.environ["DATABASE_URL"])

    try:
        yield None
    finally:
        sys_conn = await asyncpg.connect(
            dsn=os.environ["DATABASE_URL"],
            database="postgres",
        )
        rows = await sys_conn.fetch(
            "SELECT pid, usename, query FROM pg_stat_activity WHERE datname = $1",
            tmp_db_name,
        )
        log.info("Active connections:\n%s", rows)

        try:
            await sys_conn.execute(f"DROP DATABASE IF EXISTS {tmp_db_name}")
        finally:
            await sys_conn.close()


@pytest.fixture
async def db(tmp_db):
    try:
        db = DomainspotterDb()
        await db.connect()
        await db.migrate()
        await db.execute("TRUNCATE TABLE users CASCADE")
        await db.execute("TRUNCATE TABLE ideas CASCADE")
        yield db
        await db.close()
    except Exception as e:
        log.error("Error in db fixture: %s", e)
        raise


@pytest.fixture
async def client(db: DomainspotterDb) -> AsyncGenerator[httpx.AsyncClient, None]:
    """Create a test client"""
    async with LifespanManager(app):
        await app.state.db.close()
        app.state.db = db
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
        await db.close()


@pytest.fixture
async def auth_headers(client: httpx.AsyncClient) -> dict:
    """Create a test user and return auth headers."""
    # Register a user
    username = "test@example.com"
    password = "secure_password123"
    user_info = await client.post(
        "/api/register", json={"username": username, "password": password}
    )
    if user_info.status_code != 200:
        raise Exception(f"Failed to register user: {user_info.json()}")
    user_id = user_info.json()["user_id"]
    ts = str(int(time.time()))
    innerhash = get_passhash(username, password)
    passhash = hash_auth_request(username, innerhash, ts)
    # Login to get token
    response = await client.post(
        "/api/token", json={"username": username, "passhash": passhash, "ts": ts}
    )
    if response.status_code != 200:
        raise Exception(f"Failed to login: {response.json()}")
    token = response.json()["access_token"]

    return {"Authorization": f"Bearer {token}", "user_id": user_id}

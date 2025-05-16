import base64
import hashlib
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID

import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from pydantic import BaseModel

# load env vars before loading any app modules

load_dotenv()

# flake8: noqa: E402
from domainspotter.deps import get_current_user, get_db

from .db import AlreadyExistsError, DomainspotterDb
from .models import Idea, IdeaCreate, LeadCreate, User, UserWithPass

# flake8: enable

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

SECRET_KEY = os.environ["JWT_SECRET_KEY"]  # fail if this isn't set
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("JWT_EXPIRE_MINUTES", "60"))
GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")

log = logging.getLogger(__name__)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    log.info("Starting up")
    app.state.db = DomainspotterDb()
    await app.state.db.connect()
    await app.state.db.migrate()
    yield
    await app.state.db.close()


app = FastAPI(
    title="DomainSpotter",
    description="API for generating domain name suggestions",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Custom OpenAPI schema to exclude internal routes
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Domainspotter API",
        version="1.0.0",
        description="API for Domainspotter",
        routes=app.routes,
    )

    # Routes to exclude from documentation
    excluded_paths = {
        "/app",
        "/favicon.ico",
        "/",
        "/api",
    }

    # Filter out excluded paths
    openapi_schema["paths"] = {
        path: path_item
        for path, path_item in openapi_schema["paths"].items()
        if path not in excluded_paths
    }

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# Exception handler middleware
@app.middleware("http")
async def exception_handling_middleware(request: Request, call_next):
    try:
        return await call_next(request)
    except HTTPException:
        raise
    except Exception as e:
        log.info(f"HTTP exception: {e}")
        endpoint = request.url.path
        log.exception(f"Error in {endpoint}: {e!s}")

        # Map endpoints to specific error messages
        error_messages = {
            "/api/token": "Could not authenticate",
        }

        # Get the base path for matching
        base_path = f"/{endpoint.split('/')[1]}" if endpoint != "/" else "/"
        error_message = error_messages.get(base_path, "An unexpected error occurred")

        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"detail": error_message}
        )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: Exception):
    log.warning("422 on %s: %s", request.url.path, exc.errors())
    # optionally log request body:
    try:
        body = await request.body()
        log.debug("Request body: %s", body.decode())
    except Exception:
        pass
    return await request_validation_exception_handler(request, exc)


@app.exception_handler(401)
async def not_authorized_handler(request: Request, exc: Exception):
    if request.url.path.startswith("/api"):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED, content={"detail": "Unauthorized"}
        )
    return RedirectResponse(url="/login.html")


# Set up templates
templates = Jinja2Templates(directory="domainspotter/templates")


class UserCreate(BaseModel):
    email: str | None = None
    phone_number: str | None = None
    username: str | None = None
    password: str | None = None  # Optional for OAuth
    is_admin: bool = False


class UserRegister(UserCreate):
    organization_name: str | None = None


class AuthRequest(BaseModel):
    username: str
    passhash: str  # computed by the client as SHA256(SHA256(username:password):timestamp)
    ts: str


class GitHubAuthRequest(BaseModel):
    code: str


class Token(BaseModel):
    access_token: str
    token_type: str
    user_id: UUID
    is_admin: bool


class TokenData(BaseModel):
    user_id: UUID
    is_admin: bool


class StatusResponse(BaseModel):
    status: str


class UserCreationResponse(StatusResponse):
    user_id: UUID | None = None


class UserListResponse(BaseModel):
    users: list[User]


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


async def decode_token(
    token: str,
) -> tuple[UUID, bool]:
    """Decode a token and return the user ID and is_admin flag"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str | None = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        is_admin: bool | None = payload.get("is_admin")
        return UUID(user_id), is_admin
    except JWTError:
        raise credentials_exception


@app.post("/api/token", response_model=Token)
async def login_for_access_token(auth_request: AuthRequest, response: Response):
    """Login endpoint that returns a JWT token"""
    log.info(f"Auth request: {auth_request}")
    user = await verify_auth_request(auth_request, app.state.db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id), "is_admin": user.is_admin},
        expires_delta=access_token_expires,
    )

    # Set session cookie
    response.set_cookie(
        key="session",
        value=access_token,
        httponly=True,
        secure=os.environ.get("ENV") == "prod",  # Allow non-HTTPS in development
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "is_admin": user.is_admin,
    }


# Add a session dependency
async def get_session_token(request: Request) -> str | None:
    """Get the session token from cookies"""
    token = request.cookies.get("session")
    log.info(f"Session token from cookie: {'present' if token else 'missing'}")
    return token


# Update the get_c dependency to use session cookie
async def get_current_admin(
    token: Annotated[str, Depends(oauth2_scheme)],
) -> UUID:
    """Get the current admin from the token"""
    user_id, is_admin = await decode_token(token)
    if not is_admin:
        raise credentials_exception
    return user_id


def hash_auth_request(username: str, passhash: str, ts: str) -> str:
    """Hash the authentication request"""
    expected_hash = f"{username}:{passhash}:{ts}"
    expected_hash = base64.b64encode(hashlib.sha256(expected_hash.encode()).digest()).decode()
    return expected_hash


async def verify_auth_request(
    auth_request: AuthRequest, db: DomainspotterDb
) -> UserWithPass | None:
    """Verify the authentication request"""
    # Get the user record
    user = await db.get_user_for_auth(auth_request.username)

    log.info(f"User: {user}")

    if not user:
        return None

    # Check timestamp to prevent replay attacks (within 5 minutes)
    try:
        ts = int(auth_request.ts)
        current_ts = int(time.time())
        if abs(current_ts - ts) > 300:  # 5 minutes
            return None
    except ValueError:
        return None

    # Calculate expected hash: username:passhash:timestamp
    # The client should send: SHA256(SHA256(username:password):timestamp)
    # The datbase stores the SHA256(username:password) as passhash
    # Passwords are not stored in plaintext
    # The extra hash is to prevent replay attacks
    expected_hash = hash_auth_request(auth_request.username, user.passhash, auth_request.ts)
    if auth_request.passhash != expected_hash:
        return None

    return user


@app.get("/api/github/login")
async def github_login_redirect():
    """Redirect to GitHub OAuth login page"""
    redirect_uri = f"{os.environ.get('BASE_URL')}/api/github/token"
    return RedirectResponse(
        url=f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&redirect_uri={redirect_uri}&scope=user:email"
    )


@app.post("/api/github/token", response_model=Token)
async def github_login(github_auth: GitHubAuthRequest):
    """Login with GitHub OAuth

    The client should send the GitHub OAuth code in the request body.
    This endpoint will:
    1. Exchange the code for a GitHub access token
    2. Get the user's GitHub username
    3. Create or get the user in our database
    4. Return a JWT token
    """
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        log.warning("GitHub OAuth is not configured")
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="GitHub OAuth is not configured",
        )

    # Exchange code for access token
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": github_auth.code,
            },
            headers={"Accept": "application/json"},
        )
        if token_response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not get GitHub access token",
            )
        token_data = token_response.json()
        access_token = token_data["access_token"]

        # Get user info from GitHub
        user_response = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
        )
        if user_response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not get GitHub user info",
            )
        github_user = user_response.json()
        github_id = github_user["id"]

    # Get or create user
    user = await app.state.db.get_github_user(github_id)
    if not user:
        email = github_user.get("email")
        # Create new user with just github_id
        user_id = await app.state.db.create_user(
            github_id=github_id,
            email=email,
            is_admin=False,
        )
        is_admin = False
    else:
        is_admin = user.is_admin
        user_id = user.id

    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user_id), "is_admin": is_admin},
        expires_delta=access_token_expires,
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user_id,
        "is_admin": is_admin,
    }


@app.post("/api/register", response_model=UserCreationResponse)
async def register_user(
    user: UserRegister,
):
    """Create a new user"""
    # At least one identifier must be provided
    if not any([user.email, user.phone_number, user.username]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one of email, phone_number, or username must be provided",
        )

    if not user.username:
        user.username = user.email

    # If password is provided, username is required
    if user.password and not user.username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username is required when password is provided",
        )

    # newly registered users are automatically admins of their own organization
    try:
        user_id = await app.state.db.create_user(
            email=user.email,
            phone_number=user.phone_number,
            username=user.username,
            password=user.password,
            is_admin=True,
        )
    except AlreadyExistsError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    return {"status": "success", "user_id": user_id}


@app.post("/api/users", response_model=UserCreationResponse)
async def create_user(
    user: UserCreate,
    current_user: Annotated[UUID, Depends(get_current_user)],
    current_admin: Annotated[UUID, Depends(get_current_admin)],
):
    """Create a new user in the same organization as the current user"""
    # At least one identifier must be provided
    if not any([user.email, user.phone_number, user.username]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one of email, phone_number, or username must be provided",
        )

    # If password is provided, username is required
    if user.password and not user.username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username is required when password is provided",
        )

    current_user_info = await app.state.db.get_user_by_id(current_user)
    if not current_user_info:
        log.error(f"Current user not found: {current_user}")
        raise HTTPException(status_code=404, detail="User not found")

    if not current_user_info.org_id:
        raise HTTPException(
            status_code=400, detail="Current user does not belong to an organization"
        )

    # can only create users in the same organization
    user_id = await app.state.db.create_user(
        email=user.email,
        phone_number=user.phone_number,
        username=user.username,
        password=user.password,
        is_admin=user.is_admin,
        org_id=current_user_info.org_id,
    )
    return {"status": "success", "user_id": user_id}


@app.get("/api/users", response_model=UserListResponse)
async def list_users(current_user: Annotated[UUID, Depends(get_current_admin)]):
    """List all users (admin only)"""
    current_user_info: User = await app.state.db.get_user_by_id(current_user)
    if not current_user_info.org_id:
        # only list myself
        return {"users": [current_user_info]}
    users = await app.state.db.get_all_users(current_user_info.org_id)
    return {"users": users}


# Set routes
@app.post("/api/ideas", response_model=Idea)
async def create_idea(
    idea_data: IdeaCreate,
    user_id: uuid.UUID = Depends(get_current_user),
):
    idea_id = await app.state.db.create_idea(user_id, idea_data.name)

    # Get the created idea
    idea_info = await app.state.db.get_idea(idea_id, user_id)

    return idea_info


@app.get("/api/ideas", response_model=list[Idea])
async def get_ideas(user_id: uuid.UUID = Depends(get_current_user)):
    ideas = await app.state.db.get_ideas_by_user(user_id)
    return ideas


@app.get("/api/ideas/{idea_id}", response_model=Idea)
async def get_idea(idea_id: int, user_id: uuid.UUID = Depends(get_current_user)):
    idea_info = await app.state.db.get_idea(idea_id, user_id)

    if not idea_info:
        raise HTTPException(status_code=404, detail="Idea not found")

    return idea_info


@app.delete("/api/ideas/{idea_id}")
async def delete_idea(idea_id: int, user_id: uuid.UUID = Depends(get_current_user)):
    success = await app.state.db.delete_idea(idea_id, user_id)

    if not success:
        raise HTTPException(status_code=404, detail="Idea not found")

    return {"success": True}


app.mount("/static", StaticFiles(directory="static"), name="static")


# Handle favicon.ico requests
@app.get("/favicon.ico")
async def favicon():
    return FileResponse("static/img/favicon.ico")


@app.get("/", response_class=HTMLResponse)
async def serve_home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "now": datetime.now(UTC)})


@app.head("/")
async def head_home():
    """Handle HEAD requests for the root path"""
    return Response(headers={"Content-Type": "text/html"})


# Add a logout endpoint
@app.post("/api/logout")
async def logout(response: Response):
    """Logout endpoint that clears the session cookie"""
    response.delete_cookie("session")
    return {"status": "success"}


@app.get("/api/me")
async def get_me(current_user: UUID = Depends(get_current_user)):
    """Get current user data"""
    log.info(f"Getting user data for {current_user}")
    user = await app.state.db.get_user_by_id(current_user)
    if not user:
        log.error(f"User not found: {current_user}")
        raise HTTPException(status_code=404, detail="User not found")

    log.info(f"Found user: {user.email}")
    return {
        "id": str(user.id),
        "email": user.email,
        "username": user.username,
        "is_admin": user.is_admin,
        "org_id": str(user.org_id) if user.org_id else None,
    }


@app.post("/api/leads")
async def create_lead(
    data: LeadCreate,
    db: Annotated[DomainspotterDb, Depends(get_db)],
):
    """Create a new lead from the website."""
    try:
        lead_id = await db.create_lead(
            email=data.email,
            name=data.name,
            phone=data.phone,
            source=data.source,
            metadata=data.metadata,
        )
        return {"status": "success", "id": str(lead_id)}
    except AlreadyExistsError:
        return {"status": "success", "message": "Email already registered"}


class DashboardData(BaseModel):
    """Response model for dashboard data"""

    ideas: list[dict[str, Any]]


@app.get("/api/dashboard", response_model=DashboardData)
async def get_dashboard_data(
    current_user: Annotated[UUID, Depends(get_current_user)],
    db: Annotated[DomainspotterDb, Depends(get_db)],
):
    """Get data for the dashboard including resume banks and open jobs."""
    user = await db.get_user_by_id(current_user)
    if not user or not user.org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User must belong to an organization",
        )

    # Get resume banks with counts
    ideas = await db.get_ideas_by_user(current_user)
    ideas_data = []
    for idea in ideas:
        items, total = await db.get_idea_items(idea.id, current_user)
        total_items = total
        unprocessed_items = len([item for item in items if item.status != "ready"])
        ideas_data.append(
            {
                "id": idea.id,
                "name": idea.name,
                "total_items": total_items,
                "unprocessed_items": unprocessed_items,
                "created_at": idea.created_at,
            }
        )

    return DashboardData(ideas=ideas_data)


@app.get("/")
async def serve_page(page_name: str):
    """Serve template pages"""
    return templates.TemplateResponse("home.html", {"request": {}, "now": datetime.now(UTC)})


@app.get("/privacy")
async def serve_privacy(request: Request):
    """Serve privacy policy page"""
    return templates.TemplateResponse(
        "privacy.html", {"request": request, "now": datetime.now(UTC)}
    )


@app.get("/terms")
async def serve_terms(request: Request):
    """Serve terms of service page"""
    return templates.TemplateResponse("terms.html", {"request": request, "now": datetime.now(UTC)})


# Add 404 handler
@app.exception_handler(404)
async def not_found_handler(request: Request, exc: Exception):
    """Handle 404 errors"""
    if request.url.path.startswith("/api"):
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": "Not found"})
    return templates.TemplateResponse("404.html", {"request": request, "now": datetime.now(UTC)})


from .api import router

app.include_router(router)


def should_cache_template_response(request: Request) -> bool:
    """Return True if this request should have cache headers for template-driven pages."""
    # Only cache GET/HEAD, not API or static or favicon
    if request.method not in ("GET", "HEAD"):
        return False
    path = request.url.path
    if path.startswith("/api"):
        return False


@app.middleware("http")
async def cache_control_middleware(request: Request, call_next):
    response = await call_next(request)
    if should_cache_template_response(request):
        # 1 hour cache, allow stale for 1 day if backend is down, revalidate in background
        response.headers["Cache-Control"] = (
            "public, max-age=3600, stale-while-revalidate=3600, stale-if-error=86400"
        )
    return response

import logging
import os
from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

log = logging.getLogger(__name__)

SECRET_KEY = os.environ["JWT_SECRET_KEY"]  # fail if this isn't set
ALGORITHM = "HS256"

credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


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


async def get_session_token(request: Request) -> str | None:
    """Get the session token from cookies"""
    token = request.cookies.get("session")
    if not token:
        token = request.headers.get("Authorization")
        if token:
            token = token.split(" ")[1]
    log.info(f"Session token from cookie: {'present' if token else 'missing'}")
    return token


async def get_current_user(
    request: Request,
    token: Annotated[str, Depends(get_session_token)],
) -> UUID:
    """Get the current user from the session token"""
    if not token:
        log.warning("No session token found in cookies")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        user_id, _ = await decode_token(token)
        log.info(f"Successfully decoded token for user {user_id}")
        return user_id
    except Exception as e:
        log.error(f"Error decoding token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_admin(
    token: Annotated[str, Depends(oauth2_scheme)],
) -> UUID:
    """Get the current admin from the token"""
    user_id, is_admin = await decode_token(token)
    if not is_admin:
        raise credentials_exception
    return user_id


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_db(request: Request):
    return request.app.state.db

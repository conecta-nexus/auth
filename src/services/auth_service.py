"""Authentication application service managing credentials validation and session persistence."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.security import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS,
    verify_password,
)
from src.models.token import RefreshToken
from src.models.user import User
from src.schemas.auth import TokenResponse
from src.services.jwt_service import create_access_token, create_refresh_token


class AuthServiceError(Exception):
    """Base exception for authentication service errors."""


class InvalidCredentialsError(AuthServiceError):
    """Raised when email does not exist or password verification fails."""


class InactiveAccountError(AuthServiceError):
    """Raised when an authenticated user account has is_active = False."""


def hash_token(token: str) -> str:
    """Generate SHA-256 hash of a token string for secure database persistence."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def authenticate_user(
    db: AsyncSession,
    email: str,
    password: str,
) -> User:
    """Verify user credentials and active state.

    Args:
        db: Active asynchronous database session.
        email: User email.
        password: User plaintext password.

    Returns:
        User domain model.

    Raises:
        InvalidCredentialsError: If credentials do not match any active user.
        InactiveAccountError: If account is suspended or marked inactive.
    """
    normalized_email = email.strip().lower()
    stmt = select(User).where(func.lower(User.email) == normalized_email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not verify_password(password, user.password_hash):
        raise InvalidCredentialsError("Invalid email or password.")

    if not user.is_active:
        raise InactiveAccountError("Account is inactive or suspended.")

    # Update last login timestamp
    user.last_login_at = datetime.now(timezone.utc)
    return user


async def create_user_session(
    db: AsyncSession,
    user: User,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> TokenResponse:
    """Issue RS256 token pair and persist hashed refresh token in db_auth.

    Args:
        db: Active asynchronous database session.
        user: Authenticated User domain model.
        client_ip: Client IP address (from headers or request.client).
        user_agent: Browser or client User-Agent string.

    Returns:
        TokenResponse with access_token, refresh_token, token_type, and expires_in.
    """
    session_jti = uuid.uuid4()
    access_jti = uuid.uuid4()

    access_token = create_access_token(user, jti=access_jti)
    refresh_token = create_refresh_token(user, jti=session_jti)

    token_hash = hash_token(refresh_token)
    expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    # Sanitize user agent length
    truncated_user_agent = user_agent[:512] if user_agent else None
    truncated_ip = client_ip[:45] if client_ip else None

    refresh_token_record = RefreshToken(
        id=session_jti,
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
        is_revoked=False,
        ip_address=truncated_ip,
        user_agent=truncated_user_agent,
    )

    db.add(refresh_token_record)
    await db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


async def login_user(
    db: AsyncSession,
    email: str,
    password: str,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> TokenResponse:
    """Authenticate user credentials and establish a new session."""
    user = await authenticate_user(db, email, password)
    return await create_user_session(db, user, client_ip, user_agent)

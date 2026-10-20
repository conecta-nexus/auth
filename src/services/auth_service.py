"""Authentication application service managing credentials validation and session persistence."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.security import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS,
    hash_password,
    verify_password,
)
from src.models.token import RefreshToken
from src.models.user import User
from src.repositories.user_repository import UserRepository
from src.schemas.auth import TokenResponse
from src.schemas.user import UserCreate
from src.services.jwt_service import (
    InvalidTokenError,
    TokenExpiredError,
    create_access_token,
    create_refresh_token,
    decode_token,
)


class AuthServiceError(Exception):
    """Base exception for authentication service errors."""


class InvalidCredentialsError(AuthServiceError):
    """Raised when email does not exist or password verification fails."""


class InactiveAccountError(AuthServiceError):
    """Raised when an authenticated user account has is_active = False."""


class DuplicateEmailError(AuthServiceError):
    """Raised when a registration email is already persisted."""


class InvalidRefreshTokenError(AuthServiceError):
    """Raised when a refresh token cannot be safely rotated."""


async def register_user(db: AsyncSession, user_in: UserCreate) -> User:
    """Register a validated public user and commit the transaction."""
    existing_user = await UserRepository.get_by_email(db, str(user_in.email))
    if existing_user is not None:
        raise DuplicateEmailError("Email is already registered")

    hashed_password = hash_password(user_in.password)

    try:
        user = await UserRepository.create(db, user_in, hashed_password)
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise DuplicateEmailError("Email is already registered") from exc

    return user


def hash_token(token: str) -> str:
    """Generate SHA-256 hash of a token string for secure database persistence."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def rotate_refresh_token(
    db: AsyncSession,
    refresh_token: str,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> TokenResponse:
    """Atomically consume one refresh token and issue its replacement pair."""
    try:
        payload = decode_token(refresh_token)
    except (TokenExpiredError, InvalidTokenError) as exc:
        raise InvalidRefreshTokenError("Invalid or expired refresh token") from exc

    if payload.get("type") != "refresh":
        raise InvalidRefreshTokenError("Invalid or expired refresh token")

    try:
        user_id = uuid.UUID(str(payload["sub"]))
        consumed_jti = uuid.UUID(str(payload["jti"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise InvalidRefreshTokenError("Invalid or expired refresh token") from exc

    consumed_hash = hash_token(refresh_token)
    statement = (
        select(RefreshToken)
        .where(RefreshToken.token_hash == consumed_hash)
        .with_for_update()
    )

    try:
        result = await db.execute(statement)
        consumed_record = result.scalar_one_or_none()
        now = datetime.now(timezone.utc)

        if (
            consumed_record is None
            or consumed_record.is_revoked
            or consumed_record.expires_at <= now
            or consumed_record.id != consumed_jti
            or consumed_record.user_id != user_id
        ):
            raise InvalidRefreshTokenError("Invalid or expired refresh token")

        user = await UserRepository.get_by_id(db, user_id)
        if user is None:
            raise InvalidRefreshTokenError("Invalid or expired refresh token")
        if not user.is_active:
            raise InactiveAccountError("Account is inactive or suspended")

        consumed_record.is_revoked = True
        consumed_record.revoked_at = now

        session_jti = uuid.uuid4()
        access_jti = uuid.uuid4()
        access_token = create_access_token(user, jti=access_jti)
        rotated_refresh_token = create_refresh_token(user, jti=session_jti)
        rotated_record = RefreshToken(
            id=session_jti,
            user_id=user.id,
            token_hash=hash_token(rotated_refresh_token),
            expires_at=now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
            is_revoked=False,
            revoked_at=None,
            ip_address=client_ip[:45] if client_ip else None,
            user_agent=user_agent[:512] if user_agent else None,
        )
        db.add(rotated_record)
        await db.commit()
    except (InvalidRefreshTokenError, InactiveAccountError):
        await db.rollback()
        raise
    except Exception:
        await db.rollback()
        raise

    return TokenResponse(
        access_token=access_token,
        refresh_token=rotated_refresh_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


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

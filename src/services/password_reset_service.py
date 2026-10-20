"""Password reset application service managing token generation, consumption, and session invalidation."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.security import PASSWORD_RESET_TOKEN_EXPIRE_MINUTES, hash_password
from src.models.token import PasswordResetToken, RefreshToken
from src.repositories.user_repository import UserRepository
from src.services.auth_service import hash_token
from src.services.jwt_service import (
    InvalidTokenError,
    TokenExpiredError,
    create_password_reset_token,
    decode_token,
)


class PasswordResetServiceError(Exception):
    """Base exception for password reset service errors."""


class UserNotFoundError(PasswordResetServiceError):
    """Raised when user with the provided email or ID is not found."""


class InactiveAccountError(PasswordResetServiceError):
    """Raised when an account is inactive or suspended."""


class InvalidResetTokenError(PasswordResetServiceError):
    """Raised when password reset token is invalid, expired, or already used."""


async def request_password_reset(
    db: AsyncSession,
    email: str,
) -> str:
    """Validate user and issue a 15-minute single-use password reset token.

    Args:
        db: Active asynchronous database session.
        email: User email address.

    Returns:
        Signed RS256 password reset JWT.

    Raises:
        UserNotFoundError: If no user with the email exists.
        InactiveAccountError: If the account is deactivated.
    """
    user = await UserRepository.get_by_email(db, email)
    if user is None:
        raise UserNotFoundError("User with the provided email does not exist.")

    if not user.is_active:
        raise InactiveAccountError("Account is inactive or suspended.")

    token_jti = uuid.uuid4()
    reset_token = create_password_reset_token(
        user,
        jti=token_jti,
        expires_delta=timedelta(minutes=PASSWORD_RESET_TOKEN_EXPIRE_MINUTES),
    )

    token_hash_value = hash_token(reset_token)
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=PASSWORD_RESET_TOKEN_EXPIRE_MINUTES
    )

    record = PasswordResetToken(
        id=token_jti,
        user_id=user.id,
        token_hash=token_hash_value,
        expires_at=expires_at,
        is_used=False,
    )

    db.add(record)
    await db.commit()
    return reset_token


async def confirm_password_reset(
    db: AsyncSession,
    token: str,
    new_password: str,
) -> None:
    """Consume single-use token, update user password, and revoke all active sessions.

    Args:
        db: Active asynchronous database session.
        token: RS256 password reset JWT.
        new_password: Plaintext password meeting security criteria.

    Raises:
        InvalidResetTokenError: If token is invalid, expired, or already consumed.
        UserNotFoundError: If user record cannot be located.
        InactiveAccountError: If user is inactive.
    """
    try:
        payload = decode_token(token)
    except (TokenExpiredError, InvalidTokenError) as exc:
        raise InvalidResetTokenError("Invalid or expired password reset token.") from exc

    if payload.get("type") != "password_reset":
        raise InvalidResetTokenError("Invalid or expired password reset token.")

    try:
        user_id = uuid.UUID(str(payload["sub"]))
        token_jti = uuid.UUID(str(payload["jti"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise InvalidResetTokenError("Invalid or expired password reset token.") from exc

    consumed_hash = hash_token(token)
    statement = (
        select(PasswordResetToken)
        .where(PasswordResetToken.token_hash == consumed_hash)
        .with_for_update()
    )

    try:
        result = await db.execute(statement)
        record = result.scalar_one_or_none()
        now = datetime.now(timezone.utc)

        if (
            record is None
            or record.is_used
            or record.expires_at <= now
            or record.id != token_jti
            or record.user_id != user_id
        ):
            raise InvalidResetTokenError(
                "Invalid, expired, or already used password reset token."
            )

        user = await UserRepository.get_by_id(db, user_id)
        if user is None:
            raise UserNotFoundError("User not found.")
        if not user.is_active:
            raise InactiveAccountError("Account is inactive or suspended.")

        # Mark single-use token as consumed
        record.is_used = True

        # Update password hash
        user.password_hash = hash_password(new_password)
        user.updated_at = now

        # Invalidate/revoke all active refresh tokens for the user
        revoke_statement = (
            update(RefreshToken)
            .where(
                RefreshToken.user_id == user.id,
                RefreshToken.is_revoked.is_(False),
            )
            .values(
                is_revoked=True,
                revoked_at=now,
            )
        )
        await db.execute(revoke_statement)

        await db.commit()
    except (InvalidResetTokenError, UserNotFoundError, InactiveAccountError):
        await db.rollback()
        raise
    except Exception:
        await db.rollback()
        raise

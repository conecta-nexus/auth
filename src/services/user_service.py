"""Application service for administrative user account operations."""

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from src.models.user import User
from src.repositories.user_repository import UserRepository
from src.schemas.user import UserStatusUpdate


class UserServiceError(Exception):
    """Base exception for user service errors."""


class UserNotFoundError(UserServiceError):
    """Raised when the requested user does not exist."""


async def update_user_status(
    db: AsyncSession,
    user_id: UUID,
    status_update: UserStatusUpdate,
) -> User:
    """Persist an administrative account activation or suspension."""
    user = await UserRepository.get_by_id(db, user_id)
    if user is None:
        raise UserNotFoundError("User not found")

    user.is_active = status_update.is_active
    user.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(user)
    return user

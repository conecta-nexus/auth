"""Database operations for persisted user accounts."""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.user import User
from src.schemas.user import UserCreate


class UserRepository:
    """Stateless SQLAlchemy repository for users."""

    @staticmethod
    async def get_by_email(db: AsyncSession, email: str) -> User | None:
        """Return a user matching an email case-insensitively."""
        normalized_email = email.strip().lower()
        statement = select(User).where(func.lower(User.email) == normalized_email)
        result = await db.execute(statement)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_id(db: AsyncSession, user_id: UUID) -> User | None:
        """Return a user matching its UUID primary key."""
        statement = select(User).where(User.id == user_id)
        result = await db.execute(statement)
        return result.scalar_one_or_none()

    @staticmethod
    async def create(
        db: AsyncSession,
        user_in: UserCreate,
        hashed_password: str,
    ) -> User:
        """Add a validated user to the current transaction without committing."""
        user = User(
            email=str(user_in.email),
            password_hash=hashed_password,
            role=user_in.role,
            is_active=True,
            is_email_verified=False,
        )
        db.add(user)
        await db.flush()
        await db.refresh(user)
        return user

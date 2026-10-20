"""Pydantic schemas for user registration and account responses."""

from datetime import datetime
from typing import Literal, Self
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    StrictStr,
    field_validator,
    model_validator,
)

from src.services.validation_service import (
    validate_email_domain,
    validate_password_strength,
)


class UserCreate(BaseModel):
    """Validated input for public student and company registration."""

    email: EmailStr
    password: StrictStr
    role: Literal["STUDENT", "COMPANY"]

    @field_validator("email", mode="before")
    @classmethod
    def strip_email(cls, value: object) -> object:
        """Remove surrounding whitespace before email validation."""
        return value.strip() if isinstance(value, str) else value

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> EmailStr:
        """Normalize the validated email to lowercase."""
        return str(value).lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        """Apply the shared password-strength policy."""
        if not validate_password_strength(value):
            raise ValueError("Password does not meet strength requirements.")
        return value

    @model_validator(mode="after")
    def validate_registration_domain(self) -> Self:
        """Apply the shared role-specific email-domain policy."""
        if not validate_email_domain(str(self.email), self.role):
            raise ValueError("Email domain is not allowed for this role.")
        return self


class UserResponse(BaseModel):
    """Public representation of a persisted user account."""

    id: UUID
    email: EmailStr
    role: Literal["STUDENT", "COMPANY", "ADMIN"]
    is_active: bool
    is_email_verified: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

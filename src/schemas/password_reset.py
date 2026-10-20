"""Pydantic schemas for password reset request and confirmation."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from src.services.validation_service import validate_password_strength


class PasswordResetRequest(BaseModel):
    """Payload to request a password reset token."""

    email: str = Field(description="User primary email address")


class PasswordResetRequestResponse(BaseModel):
    """Response payload after initiating a password reset request."""

    message: str = Field(
        default="Password reset instructions sent",
        description="Status message",
    )
    reset_token: str | None = Field(
        default=None,
        description="Temporary 15-minute single-use reset token",
    )


class PasswordResetConfirmRequest(BaseModel):
    """Payload to confirm password update using a reset token."""

    token: str = Field(description="Temporary single-use reset token")
    new_password: str = Field(
        min_length=8,
        description="New plaintext password satisfying complexity rules",
    )

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        """Ensure new password satisfies complexity rules."""
        if not validate_password_strength(value):
            raise ValueError(
                "Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters."
            )
        return value


class PasswordResetConfirmResponse(BaseModel):
    """Response payload after successfully confirming password reset."""

    message: str = Field(
        default="Password has been successfully updated",
        description="Status message",
    )

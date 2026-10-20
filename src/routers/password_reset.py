"""Password reset router implementing temporary token generation and confirmation."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_db
from src.schemas.password_reset import (
    PasswordResetConfirmRequest,
    PasswordResetConfirmResponse,
    PasswordResetRequest,
    PasswordResetRequestResponse,
)
from src.services.password_reset_service import (
    InactiveAccountError,
    InvalidResetTokenError,
    UserNotFoundError,
    confirm_password_reset,
    request_password_reset,
)

router = APIRouter(prefix="/api/v1/auth/password-reset", tags=["password-reset"])


@router.post(
    "/request",
    response_model=PasswordResetRequestResponse,
    status_code=status.HTTP_200_OK,
    summary="Request a password reset token",
    description="Validates account and generates a 15-minute single-use password reset token.",
    responses={
        200: {"description": "Password reset token successfully generated"},
        403: {"description": "Account is inactive or suspended"},
        404: {"description": "User email not found"},
    },
)
async def request_reset(
    payload: PasswordResetRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> PasswordResetRequestResponse:
    """Issue a 15-minute single-use password reset token for the specified user."""
    try:
        token = await request_password_reset(db, payload.email)
        return PasswordResetRequestResponse(
            message="Password reset instructions sent",
            reset_token=token,
        )
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User with the provided email does not exist",
        ) from exc
    except InactiveAccountError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive or suspended",
        ) from exc


@router.post(
    "/confirm",
    response_model=PasswordResetConfirmResponse,
    status_code=status.HTTP_200_OK,
    summary="Confirm password reset",
    description="Validates single-use reset token, updates user password, and revokes active sessions.",
    responses={
        200: {"description": "Password successfully updated"},
        400: {"description": "Invalid, expired, or already used reset token"},
        403: {"description": "Account is inactive or suspended"},
        404: {"description": "User not found"},
    },
)
async def confirm_reset(
    payload: PasswordResetConfirmRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> PasswordResetConfirmResponse:
    """Consume single-use token and update user password."""
    try:
        await confirm_password_reset(
            db,
            token=payload.token,
            new_password=payload.new_password,
        )
        return PasswordResetConfirmResponse(
            message="Password has been successfully updated"
        )
    except InvalidResetTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid, expired, or already used reset token",
        ) from exc
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        ) from exc
    except InactiveAccountError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive or suspended",
        ) from exc

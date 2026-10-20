"""Administrative user account endpoints protected by JWT RBAC."""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_db
from src.schemas.user import UserResponse, UserStatusUpdate
from src.services.jwt_service import InvalidTokenError, TokenExpiredError, decode_token
from src.services.user_service import UserNotFoundError, update_user_status


router = APIRouter(prefix="/api/v1/auth/users", tags=["users"])
bearer_scheme = HTTPBearer(auto_error=False)


def require_user_status_admin(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> dict[str, Any]:
    """Require a valid ADMIN access token with user status write scope."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(credentials.credentials)
    except TokenExpiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token signature or claims",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type: access token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw_scopes = payload.get("scope", "")
    scopes = raw_scopes.split() if isinstance(raw_scopes, str) else []
    if payload.get("role") != "ADMIN" or "user:status:write" not in scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )

    return payload


@router.patch(
    "/{user_id}/status",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    responses={
        401: {"description": "Missing or invalid access token"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "User not found"},
    },
)
async def change_user_status(
    user_id: UUID,
    payload: UserStatusUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    _admin: Annotated[dict[str, Any], Depends(require_user_status_admin)],
) -> UserResponse:
    """Activate or suspend a user account as an authorized administrator."""
    try:
        return await update_user_status(db, user_id, payload)
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        ) from exc

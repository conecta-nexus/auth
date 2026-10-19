"""Authentication endpoints for session verification and OAuth2 token operations."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.schemas.auth import VerifyResponse
from src.services.jwt_service import InvalidTokenError, TokenExpiredError, decode_token

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

bearer_scheme = HTTPBearer(auto_error=False)


@router.get(
    "/verify",
    response_model=VerifyResponse,
    summary="High-performance session verification",
    description=(
        "Stateless token signature and scope verification for API Gateway and "
        "downstream microservices with sub-50ms latency (DoD auth / RF03)."
    ),
    responses={
        200: {"description": "Session is active and token is cryptographically valid"},
        401: {"description": "Missing, expired, or invalid Bearer access token"},
    },
)
def verify_session(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> VerifyResponse:
    """Validate Bearer token statelessly using RSA public key."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    try:
        payload = decode_token(token)
    except TokenExpiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token", error_description="The token has expired"'},
        ) from exc
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token signature or claims",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        ) from exc

    # Ensure token is an access token, not a refresh token
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type: access token required",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )

    raw_scopes = payload.get("scope", "")
    scopes = raw_scopes.split() if isinstance(raw_scopes, str) and raw_scopes.strip() else []

    return VerifyResponse(
        valid=True,
        user_id=str(payload.get("sub", "")),
        email=str(payload.get("email", "")),
        role=str(payload.get("role", "")),
        scopes=scopes,
    )

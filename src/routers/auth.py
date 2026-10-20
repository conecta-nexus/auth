"""Authentication endpoints for session verification and OAuth2 token operations."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_db
from src.schemas.auth import LoginRequest, TokenResponse, VerifyResponse
from src.services.auth_service import (
    InactiveAccountError,
    InvalidCredentialsError,
    login_user,
)
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


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="OAuth2 password authentication and session initiation",
    description=(
        "Authenticates user credentials, verifies account active status, "
        "issues RS256 access and refresh tokens, and records session metadata in db_auth."
    ),
    responses={
        200: {"description": "Authentication successful, token pair issued"},
        401: {"description": "Invalid email or password"},
        403: {"description": "Account is inactive or suspended"},
    },
)
async def login(
    request: Request,
    payload: LoginRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TokenResponse:
    """Authenticate user with email and password, issuing access and refresh tokens."""
    client_ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
    if client_ip and "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    user_agent = request.headers.get("user-agent")

    try:
        return await login_user(
            db=db,
            email=payload.email,
            password=payload.password,
            client_ip=client_ip,
            user_agent=user_agent,
        )
    except InvalidCredentialsError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except InactiveAccountError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive or suspended",
        ) from exc

"""JWT Service implementing RS256 token signing and claims builder (ADR-002).

Complies with OAuth2 token requirements and the Conecta Nexus RBAC scope matrix.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Mapping
from uuid import UUID

import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError as PyJWTError

from src.core.crypto import load_private_key_pem, load_public_key_pem
from src.core.security import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    JWT_ALGORITHM,
    JWT_AUDIENCES,
    JWT_ISSUER,
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS,
    get_scopes_string_for_role,
)


class JWTServiceError(Exception):
    """Base exception for JWT service errors."""


class TokenExpiredError(JWTServiceError):
    """Raised when the JWT token has expired."""


class InvalidTokenError(JWTServiceError):
    """Raised when the JWT token is malformed, has invalid signature, or invalid claims."""


def _extract_user_attribute(user: Any, attr: str, default: Any = None) -> Any:
    """Extract an attribute from a user object or mapping."""
    if isinstance(user, Mapping):
        return user.get(attr, default)
    return getattr(user, attr, default)


def create_access_token(
    user: Any,
    jti: UUID | str | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a signed RS256 OAuth2 access token for an authenticated user.

    Payload claims include:
    - iss: https://auth.conectanexus.ufps.edu.co
    - aud: ['conecta-nexus-gateway', 'conecta-nexus-services']
    - sub: str(user.id)
    - jti: str(token_id)
    - iat, nbf, exp: timestamps
    - type: 'access'
    - email: user.email
    - role: user.role
    - is_active: bool
    - scope: mapped role scopes string

    Args:
        user: User domain model or dict containing id, email, role, and optional is_active.
        jti: Unique token/session identifier. Generated if not supplied.
        expires_delta: Optional custom duration. Defaults to 15 minutes.

    Returns:
        Encoded RS256 JWT string.
    """
    user_id = _extract_user_attribute(user, "id")
    if not user_id:
        raise ValueError("User must have an 'id' attribute.")

    email = _extract_user_attribute(user, "email", "")
    role = _extract_user_attribute(user, "role", "STUDENT")
    is_active = _extract_user_attribute(user, "is_active", True)

    token_jti = str(jti) if jti is not None else str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    lifetime = expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    exp = now + lifetime

    payload = {
        "iss": JWT_ISSUER,
        "aud": list(JWT_AUDIENCES),
        "sub": str(user_id),
        "jti": token_jti,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "type": "access",
        "email": email,
        "role": str(role).upper(),
        "is_active": bool(is_active),
        "scope": get_scopes_string_for_role(str(role)),
    }

    private_pem = load_private_key_pem()
    return jwt.encode(payload, private_pem, algorithm=JWT_ALGORITHM)


def create_refresh_token(
    user: Any,
    jti: UUID | str | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a signed RS256 OAuth2 refresh token for session renewal.

    Args:
        user: User domain model or dict containing id and role.
        jti: Unique token/session identifier (stored in db_auth refresh_tokens).
        expires_delta: Optional custom duration. Defaults to 7 days.

    Returns:
        Encoded RS256 JWT string.
    """
    user_id = _extract_user_attribute(user, "id")
    if not user_id:
        raise ValueError("User must have an 'id' attribute.")

    role = _extract_user_attribute(user, "role", "STUDENT")
    token_jti = str(jti) if jti is not None else str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    lifetime = expires_delta or timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    exp = now + lifetime

    payload = {
        "iss": JWT_ISSUER,
        "aud": list(JWT_AUDIENCES),
        "sub": str(user_id),
        "jti": token_jti,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "type": "refresh",
        "role": str(role).upper(),
    }

    private_pem = load_private_key_pem()
    return jwt.encode(payload, private_pem, algorithm=JWT_ALGORITHM)


def create_password_reset_token(
    user: Any,
    jti: UUID | str | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a signed RS256 single-use password reset token for account recovery.

    Args:
        user: User domain model or dict containing id and email.
        jti: Unique token identifier (stored in db_auth password_reset_tokens).
        expires_delta: Optional custom duration. Defaults to 15 minutes.

    Returns:
        Encoded RS256 JWT string with type='password_reset'.
    """
    user_id = _extract_user_attribute(user, "id")
    if not user_id:
        raise ValueError("User must have an 'id' attribute.")

    email = _extract_user_attribute(user, "email", "")
    token_jti = str(jti) if jti is not None else str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    lifetime = expires_delta or timedelta(minutes=PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)
    exp = now + lifetime

    payload = {
        "iss": JWT_ISSUER,
        "aud": list(JWT_AUDIENCES),
        "sub": str(user_id),
        "jti": token_jti,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "type": "password_reset",
        "email": email,
    }

    private_pem = load_private_key_pem()
    return jwt.encode(payload, private_pem, algorithm=JWT_ALGORITHM)


def decode_token(
    token: str,
    audience: str | list[str] | None = None,
    verify_exp: bool = True,
) -> dict[str, Any]:
    """Decode and verify an RS256 JWT token using the public key.

    Validates signature, issuer, audience, and expiration.

    Args:
        token: Bearer JWT string.
        audience: Expected audience. Defaults to JWT_AUDIENCES.
        verify_exp: Whether to reject expired tokens.

    Returns:
        Decoded payload dictionary.

    Raises:
        TokenExpiredError: If the token is past its expiration time.
        InvalidTokenError: If signature, audience, issuer, or structure is invalid.
    """
    public_pem = load_public_key_pem()
    expected_aud = audience or list(JWT_AUDIENCES)

    try:
        payload = jwt.decode(
            token,
            public_pem,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            audience=expected_aud,
            options={
                "verify_signature": True,
                "verify_exp": verify_exp,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
        return payload
    except ExpiredSignatureError as exc:
        raise TokenExpiredError("Token has expired.") from exc
    except PyJWTError as exc:
        raise InvalidTokenError(f"Invalid token: {exc}") from exc

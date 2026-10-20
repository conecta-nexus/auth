"""Core security, OAuth2 scopes, and RBAC matrix configuration for Conecta Nexus.

Implements RBAC permission matrix (Section 4.1) and RS256 JWT claims specifications.
"""

from __future__ import annotations

from typing import Final, List, Mapping

from pwdlib import PasswordHash
from pwdlib.exceptions import UnknownHashError


_password_hash = PasswordHash.recommended()

# JWT Cryptographic & OAuth2 Specifications
JWT_ALGORITHM: Final[str] = "RS256"
JWT_ISSUER: Final[str] = "https://auth.conectanexus.ufps.edu.co"
JWT_AUDIENCES: Final[list[str]] = [
    "conecta-nexus-gateway",
    "conecta-nexus-services",
]

ACCESS_TOKEN_EXPIRE_MINUTES: Final[int] = 15
REFRESH_TOKEN_EXPIRE_DAYS: Final[int] = 7
PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: Final[int] = 15

# RBAC OAuth2 Scopes Matrix per Role (Section 4.1)
STUDENT_SCOPES: Final[list[str]] = [
    "consent:write",
    "consent:read",
    "profile:student:read",
    "profile:student:write",
    "profile:company:read_public",
    "challenge:read",
    "application:create",
    "application:read_own",
]

COMPANY_SCOPES: Final[list[str]] = [
    "consent:write",
    "consent:read",
    "profile:company:read",
    "profile:company:write",
    "profile:student:read_public",
    "challenge:create",
    "challenge:read_own",
    "challenge:write_own",
    "application:read_received",
    "application:decide",
]

ADMIN_SCOPES: Final[list[str]] = [
    "profile:read_all",
    "challenge:read_all",
    "challenge:moderate",
    "user:status:write",
    "audit:read",
]

ROLE_SCOPES: Final[Mapping[str, list[str]]] = {
    "STUDENT": STUDENT_SCOPES,
    "COMPANY": COMPANY_SCOPES,
    "ADMIN": ADMIN_SCOPES,
}


def hash_password(plain_password: str) -> str:
    """Hash a password with Argon2id and a library-generated random salt."""
    return _password_hash.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Return whether a password matches a supported encoded hash."""
    try:
        return _password_hash.verify(plain_password, hashed_password)
    except UnknownHashError:
        return False


def get_scopes_for_role(role: str) -> List[str]:
    """Retrieve the list of granted OAuth2 scopes for a given user role.

    Args:
        role: The user role (STUDENT, COMPANY, ADMIN). Case-insensitive.

    Returns:
        List of scope strings. Returns empty list if role is unknown.
    """
    normalized_role = role.strip().upper()
    return list(ROLE_SCOPES.get(normalized_role, []))


def get_scopes_string_for_role(role: str) -> str:
    """Retrieve a space-delimited OAuth2 scope string for a given user role.

    Used directly inside the JWT `scope` claim per OAuth2 RFC 6749.
    """
    return " ".join(get_scopes_for_role(role))

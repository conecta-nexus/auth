"""Pydantic models for authentication, token verification, and sessions."""

from __future__ import annotations

from typing import List
from pydantic import BaseModel, Field


class VerifyResponse(BaseModel):
    """Response payload for session verification endpoint (GET /verify)."""

    valid: bool = Field(description="Indicates whether the access token is valid and active")
    user_id: str = Field(description="Unique global UUID of the authenticated user (claim sub)")
    email: str = Field(description="User primary email address")
    role: str = Field(description="User operational role (STUDENT, COMPANY, ADMIN)")
    scopes: List[str] = Field(description="List of authorized OAuth2 scopes granted to the user")


class TokenResponse(BaseModel):
    """OAuth2 standard token response for login and token refresh."""

    access_token: str = Field(description="RS256 signed access token")
    refresh_token: str = Field(description="RS256 signed refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(default=900, description="Access token lifetime in seconds (15 minutes)")


class LoginRequest(BaseModel):
    """Payload for user credentials authentication (POST /login)."""

    email: str = Field(description="User primary email address")
    password: str = Field(description="User plaintext password")


class TokenRefreshRequest(BaseModel):
    """Payload containing the refresh token to rotate."""

    refresh_token: str

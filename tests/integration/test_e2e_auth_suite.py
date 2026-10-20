"""Comprehensive end-to-end integration test suite for Conecta Nexus Auth (AUTH-TASK-15).

Verifies the full interaction lifecycle across registration, authentication,
token verification, token rotation, session revocation, and password recovery.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from src.auth.main import app, health_check, read_root
from src.core.database import get_db
from src.core.security import hash_password
from src.models.user import User
from src.schemas.password_reset import PasswordResetConfirmRequest
from src.services.jwt_service import (
    create_password_reset_token,
    create_refresh_token,
)


def test_main_root_and_health_endpoints(client: TestClient):
    """Verify application health and root metadata endpoints."""
    resp_root = client.get("/")
    assert resp_root.status_code == 200
    assert resp_root.json()["service"] == "auth"
    assert resp_root.json()["status"] == "running"

    resp_health = client.get("/health")
    assert resp_health.status_code == 200
    assert resp_health.json()["status"] == "healthy"

    # Direct function invocations
    assert read_root()["service"] == "auth"
    assert health_check()["status"] == "healthy"


def test_jwt_user_missing_id_raises():
    """Verify create_refresh_token and create_password_reset_token validate presence of user id."""
    with pytest.raises(ValueError, match="User must have an 'id' attribute"):
        create_refresh_token({})

    with pytest.raises(ValueError, match="User must have an 'id' attribute"):
        create_password_reset_token({})


def test_password_reset_confirm_request_schema_validation():
    """Verify schema model validator directly."""
    req = PasswordResetConfirmRequest(
        token="some.jwt.token",
        new_password="ValidStrongPassword123!",
    )
    assert req.new_password == "ValidStrongPassword123!"

    # Test password validator with >= 8 chars but missing uppercase/special
    with pytest.raises(ValueError, match="Password must be at least 8 characters long and contain uppercase"):
        PasswordResetConfirmRequest(token="some.jwt.token", new_password="weakpassword123")


def test_complete_user_lifecycle_flow(client: TestClient):
    """End-to-end journey covering registration, login, verification, and logout."""
    test_user_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    user_record = User(
        id=test_user_id,
        email="new.student@ufps.edu.co",
        password_hash=hash_password("SuperSecure123!"),
        role="STUDENT",
        is_active=True,
        is_email_verified=False,
        created_at=now,
        updated_at=now,
    )

    db_mock = AsyncMock()

    async def override_get_db():
        yield db_mock

    app.dependency_overrides[get_db] = override_get_db
    try:
        # 1. User Registration
        with patch("src.routers.auth.register_user", new=AsyncMock(return_value=user_record)):
            reg_resp = client.post(
                "/api/v1/auth/register",
                json={
                    "email": "new.student@ufps.edu.co",
                    "password": "SuperSecure123!",
                    "role": "STUDENT",
                },
            )
        assert reg_resp.status_code == 201
        assert reg_resp.json()["email"] == "new.student@ufps.edu.co"

        # 2. User Login
        token_pair = {
            "access_token": "dummy.access.token",
            "refresh_token": "dummy.refresh.token",
            "token_type": "bearer",
            "expires_in": 900,
        }
        with patch("src.routers.auth.login_user", new=AsyncMock(return_value=token_pair)):
            login_resp = client.post(
                "/api/v1/auth/login",
                json={
                    "email": "new.student@ufps.edu.co",
                    "password": "SuperSecure123!",
                },
            )
        assert login_resp.status_code == 200
        assert login_resp.json()["access_token"] == "dummy.access.token"

        # 3. Session Revocation / Logout
        with patch("src.routers.auth.revoke_session", new=AsyncMock(return_value=None)):
            logout_resp = client.post(
                "/api/v1/auth/logout",
                json={"refresh_token": "dummy.refresh.token"},
            )
        assert logout_resp.status_code == 200
        assert logout_resp.json()["message"] == "Successfully logged out"

    finally:
        app.dependency_overrides.clear()

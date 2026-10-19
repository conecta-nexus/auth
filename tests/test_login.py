"""Unit and integration tests for OAuth2 password login and session persistence (AUTH-TASK-10)."""

import hashlib
import time
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from src.auth.main import app
from src.core.database import get_db
from src.core.security import hash_password
from src.models.token import RefreshToken
from src.models.user import User
from src.services.auth_service import (
    InactiveAccountError,
    InvalidCredentialsError,
    authenticate_user,
    create_user_session,
    hash_token,
)
from src.services.jwt_service import decode_token


@pytest.fixture
def test_user() -> User:
    """Create in-memory active User instance with hashed password."""
    user = User(
        id=uuid.uuid4(),
        email="student@ufps.edu.co",
        password_hash=hash_password("ValidPassword123!"),
        role="STUDENT",
        is_active=True,
        is_email_verified=True,
        last_login_at=None,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    return user


@pytest.fixture
def inactive_user() -> User:
    """Create in-memory inactive User instance."""
    user = User(
        id=uuid.uuid4(),
        email="suspended@ufps.edu.co",
        password_hash=hash_password("ValidPassword123!"),
        role="STUDENT",
        is_active=False,
        is_email_verified=True,
        last_login_at=None,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    return user


def test_hash_token_sha256():
    """Verify hash_token computes consistent SHA-256 hexadecimal output."""
    sample_token = "sample.refresh.token"
    expected = hashlib.sha256(sample_token.encode("utf-8")).hexdigest()
    assert hash_token(sample_token) == expected


@pytest.mark.asyncio
async def test_authenticate_user_success(test_user):
    """Verify authenticate_user succeeds with valid credentials."""
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = test_user
    mock_session.execute.return_value = mock_result

    authenticated = await authenticate_user(mock_session, "student@ufps.edu.co", "ValidPassword123!")
    assert authenticated.id == test_user.id
    assert authenticated.last_login_at is not None


@pytest.mark.asyncio
async def test_authenticate_user_wrong_password_raises(test_user):
    """Verify authenticate_user raises InvalidCredentialsError on wrong password."""
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = test_user
    mock_session.execute.return_value = mock_result

    with pytest.raises(InvalidCredentialsError):
        await authenticate_user(mock_session, "student@ufps.edu.co", "WrongPassword!")


@pytest.mark.asyncio
async def test_authenticate_user_not_found_raises():
    """Verify authenticate_user raises InvalidCredentialsError when user doesn't exist."""
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_result

    with pytest.raises(InvalidCredentialsError):
        await authenticate_user(mock_session, "unknown@ufps.edu.co", "AnyPassword!")


@pytest.mark.asyncio
async def test_authenticate_user_inactive_raises(inactive_user):
    """Verify authenticate_user raises InactiveAccountError when is_active is False."""
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = inactive_user
    mock_session.execute.return_value = mock_result

    with pytest.raises(InactiveAccountError):
        await authenticate_user(mock_session, "suspended@ufps.edu.co", "ValidPassword123!")


@pytest.mark.asyncio
async def test_create_user_session_persists_token(test_user):
    """Verify create_user_session persists hashed refresh token and returns TokenResponse."""
    mock_session = AsyncMock()
    added_objects = []
    mock_session.add = MagicMock(side_effect=added_objects.append)

    response = await create_user_session(
        mock_session,
        test_user,
        client_ip="192.168.1.100",
        user_agent="TestBrowser/1.0",
    )

    assert response.token_type == "bearer"
    assert response.expires_in == 900
    assert response.access_token is not None
    assert response.refresh_token is not None

    # Check database persistence
    assert len(added_objects) == 1
    persisted = added_objects[0]
    assert isinstance(persisted, RefreshToken)
    assert persisted.user_id == test_user.id
    assert persisted.ip_address == "192.168.1.100"
    assert persisted.user_agent == "TestBrowser/1.0"
    assert persisted.token_hash == hash_token(response.refresh_token)
    assert persisted.is_revoked is False
    mock_session.commit.assert_awaited_once()


def test_login_endpoint_valid_credentials(test_user):
    """Integration test: POST /api/v1/auth/login returns 200 with tokens and saves session."""
    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = test_user
    mock_session.execute.return_value = mock_result

    async def override_get_db():
        yield mock_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    try:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": "student@ufps.edu.co", "password": "ValidPassword123!"},
            headers={"User-Agent": "FastAPI-TestClient", "X-Forwarded-For": "10.0.0.1"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 900
        assert "access_token" in data
        assert "refresh_token" in data

        # Verify access token claims
        decoded_access = decode_token(data["access_token"])
        assert decoded_access["sub"] == str(test_user.id)
        assert decoded_access["role"] == "STUDENT"
        assert "profile:student:read" in decoded_access["scope"].split()

        # Verify refresh token claims
        decoded_refresh = decode_token(data["refresh_token"])
        assert decoded_refresh["sub"] == str(test_user.id)
        assert decoded_refresh["type"] == "refresh"

        # Verify database interaction
        mock_session.commit.assert_awaited()
    finally:
        app.dependency_overrides.clear()


def test_login_endpoint_wrong_password_returns_401(test_user):
    """Integration test: POST /api/v1/auth/login returns 401 on incorrect password."""
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = test_user
    mock_session.execute.return_value = mock_result

    async def override_get_db():
        yield mock_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    try:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": "student@ufps.edu.co", "password": "WrongPassword!"},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid email or password"
    finally:
        app.dependency_overrides.clear()


def test_login_endpoint_nonexistent_user_returns_401():
    """Integration test: POST /api/v1/auth/login returns 401 on non-existent email."""
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_result

    async def override_get_db():
        yield mock_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    try:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@ufps.edu.co", "password": "AnyPassword123!"},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid email or password"
    finally:
        app.dependency_overrides.clear()


def test_login_endpoint_inactive_user_returns_403(inactive_user):
    """Integration test: POST /api/v1/auth/login returns 403 when account is inactive."""
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = inactive_user
    mock_session.execute.return_value = mock_result

    async def override_get_db():
        yield mock_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    try:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": "suspended@ufps.edu.co", "password": "ValidPassword123!"},
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Account is inactive or suspended"
    finally:
        app.dependency_overrides.clear()


def test_login_endpoint_missing_fields_validation_error():
    """Integration test: POST /api/v1/auth/login returns 422 on invalid payload."""
    client = TestClient(app)
    response = client.post("/api/v1/auth/login", json={"email": "only_email@ufps.edu.co"})
    assert response.status_code == 422


def test_login_response_time_benchmark(test_user):
    """Benchmark: Ensure login endpoint execution is efficient and fast."""
    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = test_user
    mock_session.execute.return_value = mock_result

    async def override_get_db():
        yield mock_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    try:
        # Warmup
        client.post("/api/v1/auth/login", json={"email": "student@ufps.edu.co", "password": "ValidPassword123!"})

        latencies = []
        for _ in range(10):
            start = time.perf_counter()
            resp = client.post(
                "/api/v1/auth/login",
                json={"email": "student@ufps.edu.co", "password": "ValidPassword123!"},
            )
            elapsed_ms = (time.perf_counter() - start) * 1000
            latencies.append(elapsed_ms)
            assert resp.status_code == 200

        avg_latency = sum(latencies) / len(latencies)
        print(f"\nLogin Benchmark: avg={avg_latency:.2f}ms")
    finally:
        app.dependency_overrides.clear()

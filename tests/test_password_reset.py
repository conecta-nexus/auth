"""Tests for password reset flow endpoints and service (AUTH-TASK-14)."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth.main import app
from src.core.database import get_db
from src.core.security import hash_password, verify_password
from src.models.token import PasswordResetToken, RefreshToken
from src.models.user import User
from src.repositories.user_repository import UserRepository
from src.services.auth_service import hash_token
from src.services.jwt_service import (
    create_access_token,
    create_password_reset_token,
    create_refresh_token,
    decode_token,
)
from src.services.password_reset_service import (
    InactiveAccountError,
    InvalidResetTokenError,
    UserNotFoundError,
    confirm_password_reset,
    request_password_reset,
)


def _user(*, is_active: bool = True) -> User:
    now = datetime.now(timezone.utc)
    return User(
        id=uuid4(),
        email="student@ufps.edu.co",
        password_hash=hash_password("OldPassword123!"),
        role="STUDENT",
        is_active=is_active,
        is_email_verified=True,
        created_at=now,
        updated_at=now,
    )


def _reset_token_record(
    user: User,
    token: str,
    jti,
    *,
    is_used: bool = False,
    expires_at: datetime | None = None,
) -> PasswordResetToken:
    return PasswordResetToken(
        id=jti,
        user_id=user.id,
        token_hash=hash_token(token),
        expires_at=expires_at or datetime.now(timezone.utc) + timedelta(minutes=15),
        is_used=is_used,
    )


def _session_returning(record: PasswordResetToken | None) -> tuple[MagicMock, MagicMock]:
    result = MagicMock()
    result.scalar_one_or_none.return_value = record
    db = MagicMock(spec=AsyncSession)
    db.execute = AsyncMock(return_value=result)
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    return db, result


def test_create_password_reset_token_claims():
    """Verify password reset token embeds correct claims, 15m expiration, and RS256 signature."""
    user = _user()
    token_jti = uuid4()
    token = create_password_reset_token(user, jti=token_jti)
    payload = decode_token(token)

    assert payload["type"] == "password_reset"
    assert payload["sub"] == str(user.id)
    assert payload["email"] == user.email
    assert payload["jti"] == str(token_jti)
    assert payload["exp"] - payload["iat"] == 15 * 60


@pytest.mark.asyncio
async def test_request_password_reset_persists_record_and_returns_token():
    user = _user()
    db = MagicMock(spec=AsyncSession)
    db.add = MagicMock()
    db.commit = AsyncMock()

    with patch.object(UserRepository, "get_by_email", new=AsyncMock(return_value=user)):
        token = await request_password_reset(db, user.email)

    assert token is not None
    payload = decode_token(token)
    assert payload["type"] == "password_reset"
    assert payload["email"] == user.email

    db.add.assert_called_once()
    record = db.add.call_args.args[0]
    assert isinstance(record, PasswordResetToken)
    assert record.user_id == user.id
    assert record.token_hash == hash_token(token)
    assert record.is_used is False
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_request_password_reset_user_not_found():
    db = MagicMock(spec=AsyncSession)
    with patch.object(UserRepository, "get_by_email", new=AsyncMock(return_value=None)):
        with pytest.raises(UserNotFoundError):
            await request_password_reset(db, "unknown@ufps.edu.co")


@pytest.mark.asyncio
async def test_request_password_reset_inactive_user():
    user = _user(is_active=False)
    db = MagicMock(spec=AsyncSession)
    with patch.object(UserRepository, "get_by_email", new=AsyncMock(return_value=user)):
        with pytest.raises(InactiveAccountError):
            await request_password_reset(db, user.email)


@pytest.mark.asyncio
async def test_confirm_password_reset_success():
    user = _user()
    jti = uuid4()
    token = create_password_reset_token(user, jti=jti)
    record = _reset_token_record(user, token, jti)
    db, result = _session_returning(record)

    new_password = "NewStrongPassword456!"

    with patch.object(UserRepository, "get_by_id", new=AsyncMock(return_value=user)):
        await confirm_password_reset(db, token, new_password)

    statement = db.execute.await_args_list[0].args[0]
    compiled = str(statement.compile(dialect=postgresql.dialect())).upper()
    assert "FOR UPDATE" in compiled

    # Token consumption verification
    assert record.is_used is True

    # Password update verification
    assert verify_password(new_password, user.password_hash) is True

    # Revoke statement verification
    assert db.execute.await_count == 2
    revoke_stmt = db.execute.await_args_list[1].args[0]
    revoke_compiled = str(revoke_stmt.compile(dialect=postgresql.dialect())).upper()
    assert "UPDATE REFRESH_TOKENS" in revoke_compiled

    db.commit.assert_awaited_once()
    db.rollback.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["invalid", "expired", "wrong_type", "bad_jti", "bad_sub"])
async def test_confirm_password_reset_rejects_invalid_jwt(case: str):
    user = _user()
    db, _ = _session_returning(None)
    token = "malformed-jwt"

    if case == "expired":
        token = create_password_reset_token(user, expires_delta=timedelta(seconds=-1))
    elif case == "wrong_type":
        token = create_access_token(user)
    elif case == "bad_jti":
        token = create_password_reset_token(user)
        with patch("src.services.password_reset_service.decode_token", return_value={"type": "password_reset", "sub": str(user.id), "jti": "bad-jti"}):
            with pytest.raises(InvalidResetTokenError):
                await confirm_password_reset(db, token, "NewPass123!")
            return
    elif case == "bad_sub":
        token = create_password_reset_token(user)
        with patch("src.services.password_reset_service.decode_token", return_value={"type": "password_reset", "sub": "bad-sub", "jti": str(uuid4())}):
            with pytest.raises(InvalidResetTokenError):
                await confirm_password_reset(db, token, "NewPass123!")
            return

    with pytest.raises(InvalidResetTokenError):
        await confirm_password_reset(db, token, "NewPass123!")

    db.execute.assert_not_awaited()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["missing", "already_used", "db_expired", "jti_mismatch", "sub_mismatch"])
async def test_confirm_password_reset_rejects_invalid_db_state(case: str):
    user = _user()
    jti = uuid4()
    token = create_password_reset_token(user, jti=jti)
    record = _reset_token_record(user, token, jti)

    if case == "missing":
        record = None
    elif case == "already_used":
        record.is_used = True
    elif case == "db_expired":
        record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    elif case == "jti_mismatch":
        record.id = uuid4()
    elif case == "sub_mismatch":
        record.user_id = uuid4()

    db, _ = _session_returning(record)

    with patch.object(UserRepository, "get_by_id", new=AsyncMock(return_value=user)):
        with pytest.raises(InvalidResetTokenError):
            await confirm_password_reset(db, token, "NewPass123!")

    db.rollback.assert_awaited_once()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_confirm_password_reset_user_inactive():
    user = _user(is_active=False)
    jti = uuid4()
    token = create_password_reset_token(user, jti=jti)
    record = _reset_token_record(user, token, jti)
    db, _ = _session_returning(record)

    with patch.object(UserRepository, "get_by_id", new=AsyncMock(return_value=user)):
        with pytest.raises(InactiveAccountError):
            await confirm_password_reset(db, token, "NewPass123!")

    db.rollback.assert_awaited_once()


@pytest.mark.asyncio
async def test_confirm_password_reset_user_not_found():
    user = _user()
    jti = uuid4()
    token = create_password_reset_token(user, jti=jti)
    record = _reset_token_record(user, token, jti)
    db, _ = _session_returning(record)

    with patch.object(UserRepository, "get_by_id", new=AsyncMock(return_value=None)):
        with pytest.raises(UserNotFoundError):
            await confirm_password_reset(db, token, "NewPass123!")

    db.rollback.assert_awaited_once()


@pytest.mark.asyncio
async def test_confirm_password_reset_rolls_back_on_commit_error():
    user = _user()
    jti = uuid4()
    token = create_password_reset_token(user, jti=jti)
    record = _reset_token_record(user, token, jti)
    db, _ = _session_returning(record)
    db.commit.side_effect = RuntimeError("database failure")

    with patch.object(UserRepository, "get_by_id", new=AsyncMock(return_value=user)):
        with pytest.raises(RuntimeError, match="database failure"):
            await confirm_password_reset(db, token, "NewPass123!")

    db.rollback.assert_awaited_once()


def _client() -> tuple[TestClient, AsyncMock]:
    db = AsyncMock()

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app), db


def test_endpoint_request_password_reset_success():
    client, _ = _client()
    try:
        with patch("src.routers.password_reset.request_password_reset", new=AsyncMock(return_value="mocked-jwt")):
            response = client.post(
                "/api/v1/auth/password-reset/request",
                json={"email": "student@ufps.edu.co"},
            )
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Password reset instructions sent"
        assert data["reset_token"] == "mocked-jwt"
    finally:
        app.dependency_overrides.clear()


def test_endpoint_request_password_reset_user_not_found():
    client, _ = _client()
    try:
        with patch(
            "src.routers.password_reset.request_password_reset",
            new=AsyncMock(side_effect=UserNotFoundError("User not found")),
        ):
            response = client.post(
                "/api/v1/auth/password-reset/request",
                json={"email": "unknown@ufps.edu.co"},
            )
        assert response.status_code == 404
        assert response.json()["detail"] == "User with the provided email does not exist"
    finally:
        app.dependency_overrides.clear()


def test_endpoint_request_password_reset_inactive_user():
    client, _ = _client()
    try:
        with patch(
            "src.routers.password_reset.request_password_reset",
            new=AsyncMock(side_effect=InactiveAccountError("Account inactive")),
        ):
            response = client.post(
                "/api/v1/auth/password-reset/request",
                json={"email": "inactive@ufps.edu.co"},
            )
        assert response.status_code == 403
        assert response.json()["detail"] == "Account is inactive or suspended"
    finally:
        app.dependency_overrides.clear()


def test_endpoint_confirm_password_reset_success():
    client, _ = _client()
    try:
        with patch("src.routers.password_reset.confirm_password_reset", new=AsyncMock(return_value=None)):
            response = client.post(
                "/api/v1/auth/password-reset/confirm",
                json={"token": "valid-token", "new_password": "NewStrongPass123!"},
            )
        assert response.status_code == 200
        assert response.json()["message"] == "Password has been successfully updated"
    finally:
        app.dependency_overrides.clear()


def test_endpoint_confirm_password_reset_weak_password():
    client, _ = _client()
    try:
        response = client.post(
            "/api/v1/auth/password-reset/confirm",
            json={"token": "valid-token", "new_password": "weak"},
        )
        assert response.status_code == 422
    finally:
        app.dependency_overrides.clear()


def test_endpoint_confirm_password_reset_invalid_token():
    client, _ = _client()
    try:
        with patch(
            "src.routers.password_reset.confirm_password_reset",
            new=AsyncMock(side_effect=InvalidResetTokenError("Invalid token")),
        ):
            response = client.post(
                "/api/v1/auth/password-reset/confirm",
                json={"token": "bad-token", "new_password": "NewStrongPass123!"},
            )
        assert response.status_code == 400
        assert response.json()["detail"] == "Invalid, expired, or already used reset token"
    finally:
        app.dependency_overrides.clear()


def test_endpoint_confirm_password_reset_user_not_found():
    client, _ = _client()
    try:
        with patch(
            "src.routers.password_reset.confirm_password_reset",
            new=AsyncMock(side_effect=UserNotFoundError("User not found")),
        ):
            response = client.post(
                "/api/v1/auth/password-reset/confirm",
                json={"token": "token", "new_password": "NewStrongPass123!"},
            )
        assert response.status_code == 404
        assert response.json()["detail"] == "User not found"
    finally:
        app.dependency_overrides.clear()


def test_endpoint_confirm_password_reset_user_inactive():
    client, _ = _client()
    try:
        with patch(
            "src.routers.password_reset.confirm_password_reset",
            new=AsyncMock(side_effect=InactiveAccountError("Inactive account")),
        ):
            response = client.post(
                "/api/v1/auth/password-reset/confirm",
                json={"token": "token", "new_password": "NewStrongPass123!"},
            )
        assert response.status_code == 403
        assert response.json()["detail"] == "Account is inactive or suspended"
    finally:
        app.dependency_overrides.clear()

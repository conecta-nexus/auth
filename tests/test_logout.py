"""Tests for session revocation and logout endpoint (AUTH-TASK-12)."""

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
from src.models.token import RefreshToken
from src.models.user import User
from src.services.auth_service import (
    InvalidRefreshTokenError,
    hash_token,
    revoke_session,
    rotate_refresh_token,
)
from src.services.jwt_service import (
    create_access_token,
    create_refresh_token,
)


def _user(*, is_active: bool = True) -> User:
    now = datetime.now(timezone.utc)
    return User(
        id=uuid4(),
        email="student@ufps.edu.co",
        password_hash="$argon2id$test-only-hash",
        role="STUDENT",
        is_active=is_active,
        is_email_verified=True,
        created_at=now,
        updated_at=now,
    )


def _token_record(
    user: User,
    token: str,
    jti,
    *,
    is_revoked: bool = False,
    expires_at: datetime | None = None,
) -> RefreshToken:
    return RefreshToken(
        id=jti,
        user_id=user.id,
        token_hash=hash_token(token),
        expires_at=expires_at or datetime.now(timezone.utc) + timedelta(days=1),
        is_revoked=is_revoked,
        revoked_at=datetime.now(timezone.utc) if is_revoked else None,
    )


def _session_returning(record: RefreshToken | None) -> tuple[MagicMock, MagicMock]:
    result = MagicMock()
    result.scalar_one_or_none.return_value = record
    db = MagicMock(spec=AsyncSession)
    db.execute = AsyncMock(return_value=result)
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    return db, result


@pytest.mark.asyncio
async def test_revoke_session_locks_and_marks_token_revoked() -> None:
    user = _user()
    session_jti = uuid4()
    token = create_refresh_token(user, jti=session_jti)
    record = _token_record(user, token, session_jti)
    db, result = _session_returning(record)

    await revoke_session(db, token)

    statement = db.execute.await_args.args[0]
    compiled = str(statement.compile(dialect=postgresql.dialect())).upper()
    assert "FOR UPDATE" in compiled
    assert list(statement.compile(dialect=postgresql.dialect()).params.values()) == [
        hash_token(token)
    ]
    result.scalar_one_or_none.assert_called_once_with()
    assert record.is_revoked is True
    assert record.revoked_at is not None
    db.commit.assert_awaited_once_with()
    db.rollback.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["invalid", "expired", "access", "jti", "sub"])
async def test_revoke_session_rejects_invalid_jwt_before_db(case: str) -> None:
    user = _user()
    db, _ = _session_returning(None)
    token = "invalid-token"
    decode_patch = None

    if case == "expired":
        token = create_refresh_token(user, expires_delta=timedelta(seconds=-1))
    elif case == "access":
        token = create_access_token(user)
    elif case == "jti":
        decode_patch = patch(
            "src.services.auth_service.decode_token",
            return_value={"type": "refresh", "sub": str(user.id), "jti": "invalid-jti"},
        )
    elif case == "sub":
        decode_patch = patch(
            "src.services.auth_service.decode_token",
            return_value={"type": "refresh", "sub": "invalid-sub", "jti": str(uuid4())},
        )

    if decode_patch is None:
        with pytest.raises(InvalidRefreshTokenError):
            await revoke_session(db, token)
    else:
        with decode_patch, pytest.raises(InvalidRefreshTokenError):
            await revoke_session(db, token)

    db.execute.assert_not_awaited()
    db.commit.assert_not_awaited()
    db.rollback.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    ["missing", "already_revoked", "db_expired", "jti_mismatch", "sub_mismatch"],
)
async def test_revoke_session_rejects_invalid_persisted_record_and_rolls_back(case: str) -> None:
    user = _user()
    jti = uuid4()
    token = create_refresh_token(user, jti=jti)
    record = _token_record(user, token, jti)

    if case == "missing":
        record = None
    elif case == "already_revoked":
        record.is_revoked = True
    elif case == "db_expired":
        record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    elif case == "jti_mismatch":
        record.id = uuid4()
    elif case == "sub_mismatch":
        record.user_id = uuid4()

    db, _ = _session_returning(record)

    with pytest.raises(InvalidRefreshTokenError):
        await revoke_session(db, token)

    db.rollback.assert_awaited_once_with()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_revoke_session_rolls_back_on_commit_failure() -> None:
    user = _user()
    jti = uuid4()
    token = create_refresh_token(user, jti=jti)
    record = _token_record(user, token, jti)
    db, _ = _session_returning(record)
    db.commit.side_effect = RuntimeError("database connection failure")

    with pytest.raises(RuntimeError, match="database connection failure"):
        await revoke_session(db, token)

    db.rollback.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_attempted_reuse_after_revocation_fails() -> None:
    """Verify that after revocation, subsequent refresh or revocation attempts fail."""
    user = _user()
    session_jti = uuid4()
    token = create_refresh_token(user, jti=session_jti)
    record = _token_record(user, token, session_jti)
    db, result = _session_returning(record)

    # First revocation succeeds
    await revoke_session(db, token)
    assert record.is_revoked is True

    # Subsequent refresh attempt with the revoked token must fail with 401 / InvalidRefreshTokenError
    result.scalar_one_or_none.return_value = record
    with pytest.raises(InvalidRefreshTokenError):
        await rotate_refresh_token(db, token)

    # Subsequent logout attempt with the same already revoked token must also fail
    with pytest.raises(InvalidRefreshTokenError):
        await revoke_session(db, token)


def _post_logout(body: dict[str, object] | None = None, headers: dict[str, str] | None = None) -> Response:
    db = AsyncMock()

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        kwargs: dict[str, object] = {"headers": headers or {}}
        if body is not None:
            kwargs["json"] = body
        return TestClient(app).post("/api/v1/auth/logout", **kwargs)
    finally:
        app.dependency_overrides.clear()


def test_logout_endpoint_success_with_json_body() -> None:
    revoke_mock = AsyncMock(return_value=None)
    with patch("src.routers.auth.revoke_session", revoke_mock):
        response = _post_logout(body={"refresh_token": "valid-refresh-token"})

    assert response.status_code == 200
    assert response.json() == {"message": "Successfully logged out"}
    assert revoke_mock.await_args.kwargs["refresh_token"] == "valid-refresh-token"


def test_logout_endpoint_success_with_bearer_authorization_header() -> None:
    revoke_mock = AsyncMock(return_value=None)
    with patch("src.routers.auth.revoke_session", revoke_mock):
        response = _post_logout(
            body=None,
            headers={"Authorization": "Bearer valid-bearer-token"},
        )

    assert response.status_code == 200
    assert response.json() == {"message": "Successfully logged out"}
    assert revoke_mock.await_args.kwargs["refresh_token"] == "valid-bearer-token"


def test_logout_endpoint_prefers_body_over_header_when_both_present() -> None:
    revoke_mock = AsyncMock(return_value=None)
    with patch("src.routers.auth.revoke_session", revoke_mock):
        response = _post_logout(
            body={"refresh_token": "body-token"},
            headers={"Authorization": "Bearer header-token"},
        )

    assert response.status_code == 200
    assert response.json() == {"message": "Successfully logged out"}
    assert revoke_mock.await_args.kwargs["refresh_token"] == "body-token"


def test_logout_endpoint_missing_token_returns_401() -> None:
    revoke_mock = AsyncMock()
    with patch("src.routers.auth.revoke_session", revoke_mock):
        response = _post_logout(body=None, headers={})

    assert response.status_code == 401
    assert response.json() == {"detail": "Missing refresh token"}
    assert response.headers["www-authenticate"] == "Bearer"
    revoke_mock.assert_not_awaited()


def test_logout_endpoint_empty_body_without_header_returns_401() -> None:
    revoke_mock = AsyncMock()
    with patch("src.routers.auth.revoke_session", revoke_mock):
        response = _post_logout(body={}, headers={})

    assert response.status_code == 401
    assert response.json() == {"detail": "Missing refresh token"}
    assert response.headers["www-authenticate"] == "Bearer"
    revoke_mock.assert_not_awaited()


def test_logout_endpoint_invalid_or_revoked_token_returns_401() -> None:
    with patch(
        "src.routers.auth.revoke_session",
        new=AsyncMock(side_effect=InvalidRefreshTokenError("Invalid or expired refresh token")),
    ):
        response = _post_logout(body={"refresh_token": "revoked-or-invalid-token"})

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or expired refresh token"}
    assert response.headers["www-authenticate"] == "Bearer"

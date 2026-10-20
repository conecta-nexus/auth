"""Tests for strict refresh token rotation and its HTTP endpoint."""

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
from src.repositories.user_repository import UserRepository
from src.schemas.auth import TokenResponse
from src.services.auth_service import (
    InactiveAccountError,
    InvalidRefreshTokenError,
    hash_token,
    rotate_refresh_token,
)
from src.services.jwt_service import (
    create_access_token,
    create_refresh_token,
    decode_token,
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
async def test_rotate_refresh_token_validates_locks_and_persists_safe_pair() -> None:
    user = _user()
    consumed_jti = uuid4()
    consumed_token = create_refresh_token(user, jti=consumed_jti)
    consumed_record = _token_record(user, consumed_token, consumed_jti)
    db, result = _session_returning(consumed_record)
    long_ip = "1" * 50
    long_user_agent = "browser" * 100

    with patch.object(
        UserRepository,
        "get_by_id",
        new=AsyncMock(return_value=user),
    ) as get_by_id:
        response = await rotate_refresh_token(
            db,
            consumed_token,
            client_ip=long_ip,
            user_agent=long_user_agent,
        )

    statement = db.execute.await_args.args[0]
    compiled = str(statement.compile(dialect=postgresql.dialect())).upper()
    assert "FOR UPDATE" in compiled
    assert list(statement.compile(dialect=postgresql.dialect()).params.values()) == [
        hash_token(consumed_token)
    ]
    result.scalar_one_or_none.assert_called_once_with()
    get_by_id.assert_awaited_once_with(db, user.id)
    assert consumed_record.is_revoked is True
    assert consumed_record.revoked_at is not None

    db.add.assert_called_once()
    rotated_record = db.add.call_args.args[0]
    assert isinstance(rotated_record, RefreshToken)
    assert rotated_record.id != consumed_record.id
    assert rotated_record.user_id == user.id
    assert rotated_record.token_hash == hash_token(response.refresh_token)
    assert rotated_record.token_hash != response.refresh_token
    assert rotated_record.is_revoked is False
    assert rotated_record.revoked_at is None
    assert rotated_record.ip_address == long_ip[:45]
    assert rotated_record.user_agent == long_user_agent[:512]
    db.commit.assert_awaited_once_with()
    db.rollback.assert_not_awaited()

    access_payload = decode_token(response.access_token)
    refresh_payload = decode_token(response.refresh_token)
    assert access_payload["type"] == "access"
    assert access_payload["sub"] == str(user.id)
    assert access_payload["email"] == user.email
    assert access_payload["role"] == user.role
    assert refresh_payload["type"] == "refresh"
    assert refresh_payload["sub"] == str(user.id)
    assert refresh_payload["role"] == user.role
    assert refresh_payload["jti"] == str(rotated_record.id)
    assert response.refresh_token != consumed_token
    assert response.token_type == "bearer"
    assert response.expires_in == 900


@pytest.mark.asyncio
async def test_rotation_chain_rejects_reuse_and_allows_new_token() -> None:
    user = _user()
    first_jti = uuid4()
    first_token = create_refresh_token(user, jti=first_jti)
    first_record = _token_record(user, first_token, first_jti)
    db, result = _session_returning(first_record)

    with patch.object(
        UserRepository,
        "get_by_id",
        new=AsyncMock(return_value=user),
    ):
        second_pair = await rotate_refresh_token(db, first_token)
        second_record = db.add.call_args.args[0]

        result.scalar_one_or_none.return_value = first_record
        with pytest.raises(InvalidRefreshTokenError):
            await rotate_refresh_token(db, first_token)

        result.scalar_one_or_none.return_value = second_record
        third_pair = await rotate_refresh_token(db, second_pair.refresh_token)

    assert first_record.is_revoked is True
    assert second_record.is_revoked is True
    assert third_pair.refresh_token != second_pair.refresh_token
    assert db.add.call_count == 2
    assert db.commit.await_count == 2
    assert db.rollback.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["invalid", "expired", "access", "jti", "sub"])
async def test_rotation_rejects_invalid_jwt_before_database_access(case: str) -> None:
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
            return_value={"type": "refresh", "sub": str(user.id), "jti": "invalid"},
        )
    elif case == "sub":
        decode_patch = patch(
            "src.services.auth_service.decode_token",
            return_value={"type": "refresh", "sub": "invalid", "jti": str(uuid4())},
        )

    if decode_patch is None:
        with pytest.raises(InvalidRefreshTokenError):
            await rotate_refresh_token(db, token)
    else:
        with decode_patch, pytest.raises(InvalidRefreshTokenError):
            await rotate_refresh_token(db, token)

    db.execute.assert_not_awaited()
    db.commit.assert_not_awaited()
    db.rollback.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    ["missing", "revoked", "db_expired", "jti_mismatch", "sub_mismatch", "user_missing"],
)
async def test_rotation_rejects_invalid_persisted_state_and_rolls_back(
    case: str,
) -> None:
    user = _user()
    jti = uuid4()
    token = create_refresh_token(user, jti=jti)
    record = _token_record(user, token, jti)
    if case == "missing":
        record = None
    elif case == "revoked":
        record.is_revoked = True
    elif case == "db_expired":
        record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    elif case == "jti_mismatch":
        record.id = uuid4()
    elif case == "sub_mismatch":
        record.user_id = uuid4()

    db, _ = _session_returning(record)
    persisted_user = None if case == "user_missing" else user
    with patch.object(
        UserRepository,
        "get_by_id",
        new=AsyncMock(return_value=persisted_user),
    ):
        with pytest.raises(InvalidRefreshTokenError):
            await rotate_refresh_token(db, token)

    db.rollback.assert_awaited_once_with()
    db.commit.assert_not_awaited()
    db.add.assert_not_called()


@pytest.mark.asyncio
async def test_rotation_rejects_inactive_user_and_rolls_back() -> None:
    user = _user(is_active=False)
    jti = uuid4()
    token = create_refresh_token(user, jti=jti)
    db, _ = _session_returning(_token_record(user, token, jti))

    with patch.object(
        UserRepository,
        "get_by_id",
        new=AsyncMock(return_value=user),
    ):
        with pytest.raises(InactiveAccountError):
            await rotate_refresh_token(db, token)

    db.rollback.assert_awaited_once_with()
    db.commit.assert_not_awaited()
    db.add.assert_not_called()


@pytest.mark.asyncio
async def test_rotation_rolls_back_commit_failure() -> None:
    user = _user()
    jti = uuid4()
    token = create_refresh_token(user, jti=jti)
    record = _token_record(user, token, jti)
    db, _ = _session_returning(record)
    db.commit.side_effect = RuntimeError("database unavailable")

    with patch.object(
        UserRepository,
        "get_by_id",
        new=AsyncMock(return_value=user),
    ):
        with pytest.raises(RuntimeError, match="database unavailable"):
            await rotate_refresh_token(db, token)

    db.rollback.assert_awaited_once_with()


def _post_refresh(body: dict[str, object], headers: dict[str, str] | None = None) -> Response:
    db = AsyncMock()

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app).post(
        "/api/v1/auth/refresh",
        json=body,
        headers=headers or {},
    )


def test_refresh_endpoint_returns_token_pair_and_client_metadata() -> None:
    token_response = TokenResponse(
        access_token="new-access-token",
        refresh_token="new-refresh-token",
        token_type="bearer",
        expires_in=900,
    )
    rotate_mock = AsyncMock(return_value=token_response)

    try:
        with patch("src.routers.auth.rotate_refresh_token", rotate_mock):
            response = _post_refresh(
                {"refresh_token": "old-refresh-token"},
                {
                    "X-Forwarded-For": "203.0.113.10, 198.51.100.2",
                    "User-Agent": "RotationClient/1.0",
                },
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() == token_response.model_dump()
    assert rotate_mock.await_args.kwargs["refresh_token"] == "old-refresh-token"
    assert rotate_mock.await_args.kwargs["client_ip"] == "203.0.113.10"
    assert rotate_mock.await_args.kwargs["user_agent"] == "RotationClient/1.0"


@pytest.mark.parametrize(
    ("error", "expected_status", "expected_detail"),
    [
        (
            InvalidRefreshTokenError("Invalid or expired refresh token"),
            401,
            "Invalid or expired refresh token",
        ),
        (
            InactiveAccountError("Account is inactive or suspended"),
            403,
            "Account is inactive or suspended",
        ),
    ],
)
def test_refresh_endpoint_maps_domain_errors(
    error: Exception,
    expected_status: int,
    expected_detail: str,
) -> None:
    try:
        with patch(
            "src.routers.auth.rotate_refresh_token",
            new=AsyncMock(side_effect=error),
        ):
            response = _post_refresh({"refresh_token": "rejected-token"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == expected_status
    assert response.json() == {"detail": expected_detail}
    if expected_status == 401:
        assert response.headers["www-authenticate"] == "Bearer"


def test_refresh_endpoint_requires_refresh_token_field() -> None:
    rotate_mock = AsyncMock()

    try:
        with patch("src.routers.auth.rotate_refresh_token", rotate_mock):
            response = _post_refresh({})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 422
    rotate_mock.assert_not_awaited()

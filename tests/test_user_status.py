"""Tests for administrative user account status management."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from src.auth.main import app
from src.core.database import get_db
from src.models.user import User
from src.repositories.user_repository import UserRepository
from src.schemas.user import UserStatusUpdate
from src.services.jwt_service import create_access_token, create_refresh_token
from src.services.user_service import UserNotFoundError, update_user_status


ENDPOINT_PREFIX = "/api/v1/auth/users"


def _user(*, is_active: bool = True) -> User:
    now = datetime.now(timezone.utc)
    return User(
        id=uuid4(),
        email="target@ufps.edu.co",
        password_hash="$argon2id$test-only-hash",
        role="STUDENT",
        is_active=is_active,
        is_email_verified=True,
        created_at=now,
        updated_at=now,
    )


def _token(role: str, *, expires_delta: timedelta | None = None) -> str:
    return create_access_token(
        {
            "id": uuid4(),
            "email": f"{role.lower()}@example.com",
            "role": role,
            "is_active": True,
        },
        expires_delta=expires_delta,
    )


def _patch_status(
    user_id: UUID | str,
    body: dict[str, object],
    token: str | None,
) -> Response:
    db = AsyncMock()

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    return TestClient(app).patch(
        f"{ENDPOINT_PREFIX}/{user_id}/status",
        json=body,
        headers=headers,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("initial_status", "requested_status", "reason"),
    [
        (True, False, "Administrative suspension"),
        (False, True, None),
        (True, True, "Idempotent confirmation"),
    ],
)
async def test_update_user_status_commits_refreshes_and_returns_user(
    initial_status: bool,
    requested_status: bool,
    reason: str | None,
) -> None:
    user = _user(is_active=initial_status)
    original_updated_at = user.updated_at
    user_id = user.id
    db = AsyncMock()
    status_update = UserStatusUpdate(is_active=requested_status, reason=reason)

    with patch.object(
        UserRepository,
        "get_by_id",
        new=AsyncMock(return_value=user),
    ) as get_by_id:
        result = await update_user_status(db, user_id, status_update)

    get_by_id.assert_awaited_once_with(db, user_id)
    assert result is user
    assert user.is_active is requested_status
    assert user.updated_at >= original_updated_at
    db.commit.assert_awaited_once_with()
    db.refresh.assert_awaited_once_with(user)


@pytest.mark.asyncio
async def test_update_user_status_raises_when_user_does_not_exist() -> None:
    user_id = uuid4()
    db = AsyncMock()

    with patch.object(
        UserRepository,
        "get_by_id",
        new=AsyncMock(return_value=None),
    ) as get_by_id:
        with pytest.raises(UserNotFoundError, match="User not found"):
            await update_user_status(
                db,
                user_id,
                UserStatusUpdate(is_active=False),
            )

    get_by_id.assert_awaited_once_with(db, user_id)
    db.commit.assert_not_awaited()
    db.refresh.assert_not_awaited()


@pytest.mark.parametrize("requested_status", [False, True])
def test_admin_can_update_status_with_safe_response(requested_status: bool) -> None:
    user = _user(is_active=requested_status)
    update_mock = AsyncMock(return_value=user)

    try:
        with patch("src.routers.users.update_user_status", update_mock):
            response = _patch_status(
                user.id,
                {
                    "is_active": requested_status,
                    "reason": "Administrative status change",
                },
                _token("ADMIN"),
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() == {
        "id": str(user.id),
        "email": user.email,
        "role": user.role,
        "is_active": requested_status,
        "is_email_verified": True,
        "created_at": user.created_at.isoformat().replace("+00:00", "Z"),
    }
    assert "password" not in response.json()
    assert "password_hash" not in response.json()
    submitted_update = update_mock.await_args.args[2]
    assert submitted_update.reason == "Administrative status change"


@pytest.mark.parametrize("role", ["STUDENT", "COMPANY"])
def test_non_admin_access_tokens_are_forbidden(role: str) -> None:
    update_mock = AsyncMock()

    try:
        with patch("src.routers.users.update_user_status", update_mock):
            response = _patch_status(uuid4(), {"is_active": False}, _token(role))
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    assert response.json() == {"detail": "Insufficient permissions"}
    update_mock.assert_not_awaited()


def test_admin_without_required_scope_is_forbidden() -> None:
    update_mock = AsyncMock()
    payload = {"type": "access", "role": "ADMIN", "scope": "audit:read"}

    try:
        with (
            patch("src.routers.users.decode_token", return_value=payload),
            patch("src.routers.users.update_user_status", update_mock),
        ):
            response = _patch_status(uuid4(), {"is_active": False}, "signed-token")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    assert response.json() == {"detail": "Insufficient permissions"}
    update_mock.assert_not_awaited()


def test_missing_bearer_token_is_unauthorized() -> None:
    try:
        response = _patch_status(uuid4(), {"is_active": False}, None)
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 401
    assert response.json() == {"detail": "Missing Bearer authorization header"}


def test_invalid_token_is_unauthorized() -> None:
    try:
        response = _patch_status(uuid4(), {"is_active": False}, "invalid-token")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid token signature or claims"}


def test_expired_token_is_unauthorized() -> None:
    try:
        response = _patch_status(
            uuid4(),
            {"is_active": False},
            _token("ADMIN", expires_delta=timedelta(seconds=-1)),
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 401
    assert response.json() == {"detail": "Token has expired"}


def test_refresh_token_is_unauthorized() -> None:
    token = create_refresh_token(
        {"id": uuid4(), "email": "admin@example.com", "role": "ADMIN"}
    )

    try:
        response = _patch_status(uuid4(), {"is_active": False}, token)
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid token type: access token required"}


@pytest.mark.parametrize(
    ("user_id", "body"),
    [
        (uuid4(), {}),
        ("not-a-uuid", {"is_active": False}),
    ],
)
def test_invalid_status_requests_return_unprocessable_entity(
    user_id: UUID | str,
    body: dict[str, object],
) -> None:
    update_mock = AsyncMock()

    try:
        with patch("src.routers.users.update_user_status", update_mock):
            response = _patch_status(user_id, body, _token("ADMIN"))
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 422
    update_mock.assert_not_awaited()


def test_missing_user_returns_not_found() -> None:
    user_id = uuid4()
    update_mock = AsyncMock(side_effect=UserNotFoundError("User not found"))

    try:
        with patch("src.routers.users.update_user_status", update_mock):
            response = _patch_status(user_id, {"is_active": False}, _token("ADMIN"))
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}

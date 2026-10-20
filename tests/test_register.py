"""Tests for public user registration service and endpoint behavior."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy.exc import IntegrityError

from src.auth.main import app
from src.core.database import get_db
from src.core.security import hash_password, verify_password
from src.models.user import User
from src.repositories.user_repository import UserRepository
from src.schemas.user import UserCreate
from src.services.auth_service import DuplicateEmailError, register_user


TEST_PASSWORD = "ValidPassword123!"
TEST_HASH = "$argon2id$test-only-hash"


def _persisted_user(email: str, role: str) -> User:
    return User(
        id=uuid4(),
        email=email,
        password_hash=TEST_HASH,
        role=role,
        is_active=True,
        is_email_verified=False,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("email", "role"),
    [
        ("student@ufps.edu.co", "STUDENT"),
        ("contact@empresa.com", "COMPANY"),
    ],
)
async def test_register_user_hashes_password_creates_user_and_commits(
    email: str,
    role: str,
) -> None:
    user_in = UserCreate(email=email, password=TEST_PASSWORD, role=role)
    created_user = _persisted_user(email, role)
    db = AsyncMock()

    with (
        patch.object(
            UserRepository,
            "get_by_email",
            new=AsyncMock(return_value=None),
        ) as get_by_email,
        patch.object(
            UserRepository,
            "create",
            new=AsyncMock(return_value=created_user),
        ) as create,
        patch(
            "src.services.auth_service.hash_password",
            return_value=TEST_HASH,
        ) as password_hasher,
    ):
        result = await register_user(db, user_in)

    get_by_email.assert_awaited_once_with(db, email)
    password_hasher.assert_called_once_with(TEST_PASSWORD)
    create.assert_awaited_once_with(db, user_in, TEST_HASH)
    assert create.await_args.args[2] != TEST_PASSWORD
    db.commit.assert_awaited_once_with()
    db.rollback.assert_not_awaited()
    assert result is created_user
    assert result.password_hash == TEST_HASH
    assert not hasattr(result, "password")


@pytest.mark.asyncio
async def test_register_user_rejects_preexisting_email_without_writing() -> None:
    user_in = UserCreate(
        email="student@ufps.edu.co",
        password=TEST_PASSWORD,
        role="STUDENT",
    )
    db = AsyncMock()

    with (
        patch.object(
            UserRepository,
            "get_by_email",
            new=AsyncMock(return_value=_persisted_user(str(user_in.email), user_in.role)),
        ),
        patch.object(UserRepository, "create", new=AsyncMock()) as create,
        patch("src.services.auth_service.hash_password") as password_hasher,
    ):
        with pytest.raises(DuplicateEmailError, match="Email is already registered"):
            await register_user(db, user_in)

    password_hasher.assert_not_called()
    create.assert_not_awaited()
    db.commit.assert_not_awaited()
    db.rollback.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_point", ["create", "commit"])
async def test_register_user_rolls_back_integrity_errors(
    failure_point: str,
) -> None:
    user_in = UserCreate(
        email="student@ufps.edu.co",
        password=TEST_PASSWORD,
        role="STUDENT",
    )
    created_user = _persisted_user(str(user_in.email), user_in.role)
    integrity_error = IntegrityError("INSERT INTO users", {}, Exception("unique"))
    db = AsyncMock()
    if failure_point == "commit":
        db.commit.side_effect = integrity_error

    create_mock = (
        AsyncMock(side_effect=integrity_error)
        if failure_point == "create"
        else AsyncMock(return_value=created_user)
    )
    with (
        patch.object(
            UserRepository,
            "get_by_email",
            new=AsyncMock(return_value=None),
        ),
        patch.object(
            UserRepository,
            "create",
            new=create_mock,
        ),
        patch("src.services.auth_service.hash_password", return_value=TEST_HASH),
    ):
        with pytest.raises(DuplicateEmailError, match="Email is already registered"):
            await register_user(db, user_in)

    db.rollback.assert_awaited_once_with()
    if failure_point == "create":
        db.commit.assert_not_awaited()
    else:
        db.commit.assert_awaited_once_with()


def test_existing_password_hashing_round_trip() -> None:
    hashed_password = hash_password(TEST_PASSWORD)

    assert hashed_password != TEST_PASSWORD
    assert verify_password(TEST_PASSWORD, hashed_password) is True


def _post_registration(payload: dict[str, object]) -> Response:
    db = AsyncMock()

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    return client.post("/api/v1/auth/register", json=payload)


@pytest.mark.parametrize(
    ("email", "normalized_email", "role"),
    [
        (" Student@UFPS.EDU.CO ", "student@ufps.edu.co", "STUDENT"),
        (" Contact@Empresa.COM ", "contact@empresa.com", "COMPANY"),
    ],
)
def test_register_endpoint_returns_safe_created_response(
    email: str,
    normalized_email: str,
    role: str,
) -> None:
    created_user = _persisted_user(normalized_email, role)
    register_mock = AsyncMock(return_value=created_user)

    try:
        with patch("src.routers.auth.register_user", register_mock):
            response = _post_registration(
                {"email": email, "password": TEST_PASSWORD, "role": role}
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 201
    assert response.json() == {
        "id": str(created_user.id),
        "email": normalized_email,
        "role": role,
        "is_active": True,
        "is_email_verified": False,
        "created_at": created_user.created_at.isoformat().replace("+00:00", "Z"),
    }
    assert "password" not in response.json()
    assert "password_hash" not in response.json()
    submitted_user = register_mock.await_args.args[1]
    assert str(submitted_user.email) == normalized_email


def test_register_endpoint_returns_conflict_for_duplicate_email() -> None:
    register_mock = AsyncMock(
        side_effect=DuplicateEmailError("Email is already registered")
    )

    try:
        with patch("src.routers.auth.register_user", register_mock):
            response = _post_registration(
                {
                    "email": "student@ufps.edu.co",
                    "password": TEST_PASSWORD,
                    "role": "STUDENT",
                }
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 409
    assert response.json() == {"detail": "Email is already registered"}


@pytest.mark.parametrize(
    "payload",
    [
        {"email": "admin@ufps.edu.co", "password": TEST_PASSWORD, "role": "ADMIN"},
        {"email": "student@ufps.edu.co", "password": TEST_PASSWORD, "role": "UNKNOWN"},
        {"email": "not-an-email", "password": TEST_PASSWORD, "role": "STUDENT"},
        {"email": "student@example.com", "password": TEST_PASSWORD, "role": "STUDENT"},
        {"email": "company@gmail.com", "password": TEST_PASSWORD, "role": "COMPANY"},
        {"email": "student@ufps.edu.co", "password": "weak", "role": "STUDENT"},
        {"email": "student@ufps.edu.co", "role": "STUDENT"},
    ],
)
def test_register_endpoint_rejects_invalid_payload_before_service(
    payload: dict[str, object],
) -> None:
    register_mock = AsyncMock()

    try:
        with patch("src.routers.auth.register_user", register_mock):
            response = _post_registration(payload)
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 422
    register_mock.assert_not_awaited()

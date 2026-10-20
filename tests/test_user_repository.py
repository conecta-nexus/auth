"""Tests for user registration schemas and repository operations."""

from datetime import datetime, timezone
from uuid import UUID, uuid4
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import ValidationError
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.user import User
from src.repositories.user_repository import UserRepository
from src.schemas.user import UserCreate, UserResponse


VALID_PASSWORD = "ValidPassword1!"


def test_user_create_accepts_student_and_normalizes_email() -> None:
    user_in = UserCreate(
        email="  Student@UFPS.EDU.CO  ",
        password=VALID_PASSWORD,
        role="STUDENT",
    )

    assert str(user_in.email) == "student@ufps.edu.co"
    assert user_in.password == VALID_PASSWORD
    assert user_in.role == "STUDENT"


def test_user_create_accepts_company() -> None:
    user_in = UserCreate(
        email="Contact@Empresa.COM",
        password=VALID_PASSWORD,
        role="COMPANY",
    )

    assert str(user_in.email) == "contact@empresa.com"
    assert user_in.role == "COMPANY"


@pytest.mark.parametrize(
    ("email", "role"),
    [
        ("student@gmail.com", "STUDENT"),
        ("company@gmail.com", "COMPANY"),
        ("company@hotmail.com", "COMPANY"),
        ("company@yahoo.com", "COMPANY"),
    ],
)
def test_user_create_rejects_disallowed_domains(email: str, role: str) -> None:
    with pytest.raises(ValidationError):
        UserCreate(email=email, password=VALID_PASSWORD, role=role)


@pytest.mark.parametrize("role", ["ADMIN", "UNKNOWN", ""])
def test_user_create_rejects_unsupported_roles(role: str) -> None:
    with pytest.raises(ValidationError):
        UserCreate(
            email="student@ufps.edu.co",
            password=VALID_PASSWORD,
            role=role,
        )


def test_user_create_rejects_malformed_email() -> None:
    with pytest.raises(ValidationError):
        UserCreate(email="not-an-email", password=VALID_PASSWORD, role="STUDENT")


def test_user_create_rejects_non_string_email() -> None:
    with pytest.raises(ValidationError):
        UserCreate(email=123, password=VALID_PASSWORD, role="STUDENT")


@pytest.mark.parametrize(
    "password",
    [
        "weak",
        "lowercase1!",
        "UPPERCASE1!",
        "NoNumber!",
        "NoSymbol1",
        "Aa1!aaa",
    ],
)
def test_user_create_rejects_weak_passwords(password: str) -> None:
    with pytest.raises(ValidationError):
        UserCreate(
            email="student@ufps.edu.co",
            password=password,
            role="STUDENT",
        )


def test_user_create_rejects_non_string_password() -> None:
    with pytest.raises(ValidationError):
        UserCreate(
            email="student@ufps.edu.co",
            password=12345678,
            role="STUDENT",
        )


@pytest.mark.parametrize(
    "payload",
    [
        {"password": VALID_PASSWORD, "role": "STUDENT"},
        {"email": "student@ufps.edu.co", "role": "STUDENT"},
        {"email": "student@ufps.edu.co", "password": VALID_PASSWORD},
        {},
    ],
)
def test_user_create_rejects_missing_required_fields(payload: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        UserCreate.model_validate(payload)


def test_user_response_builds_from_admin_orm_user_without_password_hash() -> None:
    user_id = uuid4()
    created_at = datetime.now(timezone.utc)
    user = User(
        id=user_id,
        email="admin@ufps.edu.co",
        password_hash="$argon2id$test-only-hash",
        role="ADMIN",
        is_active=True,
        is_email_verified=True,
        created_at=created_at,
    )

    response = UserResponse.model_validate(user)
    dumped = response.model_dump()

    assert UserResponse.model_config["from_attributes"] is True
    assert response.id == user_id
    assert isinstance(response.id, UUID)
    assert str(response.email) == "admin@ufps.edu.co"
    assert response.role == "ADMIN"
    assert response.is_active is True
    assert response.is_email_verified is True
    assert response.created_at == created_at
    assert set(dumped) == {
        "id",
        "email",
        "role",
        "is_active",
        "is_email_verified",
        "created_at",
    }
    assert "password_hash" not in dumped


def _mock_session(return_value: User | None) -> tuple[MagicMock, MagicMock]:
    result = MagicMock()
    result.scalar_one_or_none.return_value = return_value
    db = MagicMock(spec=AsyncSession)
    db.execute = AsyncMock(return_value=result)
    db.flush = AsyncMock()
    db.refresh = AsyncMock()
    db.commit = AsyncMock()
    return db, result


@pytest.mark.asyncio
@pytest.mark.parametrize("found", [True, False])
async def test_get_by_email_executes_case_insensitive_query(found: bool) -> None:
    expected_user = MagicMock(spec=User) if found else None
    db, result = _mock_session(expected_user)

    returned_user = await UserRepository.get_by_email(
        db,
        "  Student@UFPS.EDU.CO  ",
    )

    db.execute.assert_awaited_once()
    result.scalar_one_or_none.assert_called_once_with()
    assert returned_user is expected_user

    statement = db.execute.await_args.args[0]
    assert statement.column_descriptions[0]["entity"] is User
    compiled = statement.compile(dialect=postgresql.dialect())
    assert "lower(users.email)" in str(compiled).lower()
    assert list(compiled.params.values()) == ["student@ufps.edu.co"]


@pytest.mark.asyncio
@pytest.mark.parametrize("found", [True, False])
async def test_get_by_id_executes_uuid_query(found: bool) -> None:
    user_id = uuid4()
    expected_user = MagicMock(spec=User) if found else None
    db, result = _mock_session(expected_user)

    returned_user = await UserRepository.get_by_id(db, user_id)

    db.execute.assert_awaited_once()
    result.scalar_one_or_none.assert_called_once_with()
    assert returned_user is expected_user

    statement = db.execute.await_args.args[0]
    assert statement.column_descriptions[0]["entity"] is User
    compiled = statement.compile(dialect=postgresql.dialect())
    assert "users.id" in str(compiled).lower()
    assert list(compiled.params.values()) == [user_id]


@pytest.mark.asyncio
async def test_create_adds_and_refreshes_user_without_committing() -> None:
    db, _ = _mock_session(None)
    user_in = UserCreate(
        email="  Contact@Empresa.COM  ",
        password=VALID_PASSWORD,
        role="COMPANY",
    )
    hashed_password = "$argon2id$test-only-hash"

    created_user = await UserRepository.create(db, user_in, hashed_password)

    assert isinstance(created_user, User)
    assert created_user.email == "contact@empresa.com"
    assert created_user.role == "COMPANY"
    assert created_user.password_hash == hashed_password
    assert not hasattr(created_user, "password")
    assert created_user.is_active is True
    assert created_user.is_email_verified is False
    db.add.assert_called_once_with(created_user)
    db.flush.assert_awaited_once_with()
    db.refresh.assert_awaited_once_with(created_user)
    db.commit.assert_not_awaited()

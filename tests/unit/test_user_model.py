"""Unit tests for the auth service User SQLAlchemy model."""

import os

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID


os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://test_user:test_password@localhost:5432/db_auth",
)
os.environ.setdefault("DB_ECHO", "false")
os.environ.setdefault("APP_ENV", "test")

from src.core.database import Base
from src.models.user import User


EXPECTED_COLUMNS = {
    "id",
    "email",
    "password_hash",
    "role",
    "is_active",
    "is_email_verified",
    "last_login_at",
    "created_at",
    "updated_at",
}


def test_user_table_uses_shared_metadata_and_exact_columns() -> None:
    table = User.__table__

    assert table.name == "users"
    assert table.metadata is Base.metadata
    assert set(table.columns.keys()) == EXPECTED_COLUMNS


def test_user_id_is_uuid_primary_key_with_database_default() -> None:
    column = User.__table__.c.id

    assert isinstance(column.type, PostgreSQLUUID)
    assert column.type.as_uuid is True
    assert column.primary_key is True
    assert column.nullable is False
    assert str(column.server_default.arg) == "gen_random_uuid()"


def test_user_credentials_and_role_schema() -> None:
    table = User.__table__
    email = table.c.email
    password_hash = table.c.password_hash
    role = table.c.role

    assert isinstance(email.type, String)
    assert email.type.length == 255
    assert email.nullable is False
    assert isinstance(password_hash.type, String)
    assert password_hash.type.length == 255
    assert password_hash.nullable is False
    assert isinstance(role.type, String)
    assert role.type.length == 20
    assert role.nullable is False

    unique_constraints = {
        constraint.name: {column.name for column in constraint.columns}
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    indexes = {
        index.name: ({column.name for column in index.columns}, index.unique)
        for index in table.indexes
        if isinstance(index, Index)
    }
    role_checks = {
        constraint.name: str(constraint.sqltext)
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    }

    assert unique_constraints["uq_users_email"] == {"email"}
    assert indexes["ix_users_email"] == ({"email"}, False)
    assert role_checks == {
        "ck_users_role": "role IN ('STUDENT', 'COMPANY', 'ADMIN')",
    }


def test_user_boolean_columns_have_database_defaults() -> None:
    table = User.__table__

    for column_name, expected_default in (
        ("is_active", "true"),
        ("is_email_verified", "false"),
    ):
        column = table.c[column_name]
        assert isinstance(column.type, Boolean)
        assert column.nullable is False
        assert str(column.server_default.arg) == expected_default


def test_user_timestamp_columns_are_timezone_aware() -> None:
    table = User.__table__
    last_login_at = table.c.last_login_at

    assert isinstance(last_login_at.type, DateTime)
    assert last_login_at.type.timezone is True
    assert last_login_at.nullable is True
    assert last_login_at.server_default is None

    for column_name in ("created_at", "updated_at"):
        column = table.c[column_name]
        assert isinstance(column.type, DateTime)
        assert column.type.timezone is True
        assert column.nullable is False
        assert str(column.server_default.arg) == "CURRENT_TIMESTAMP"

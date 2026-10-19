"""Structural tests for refresh and password reset token models."""

import os

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKeyConstraint,
    PrimaryKeyConstraint,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.sql.schema import Table


os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://test_user:test_password@localhost:5432/db_auth",
)
os.environ.setdefault("DB_ECHO", "false")
os.environ.setdefault("APP_ENV", "test")

from src.core.database import Base
from src.models import PasswordResetToken, RefreshToken, User


REFRESH_TOKEN_COLUMNS = {
    "id",
    "user_id",
    "token_hash",
    "expires_at",
    "is_revoked",
    "revoked_at",
    "ip_address",
    "user_agent",
    "created_at",
}
PASSWORD_RESET_TOKEN_COLUMNS = {
    "id",
    "user_id",
    "token_hash",
    "expires_at",
    "is_used",
    "created_at",
}


def _assert_identity_constraints(
    table: Table,
    primary_key_name: str,
    foreign_key_name: str,
    unique_name: str,
) -> None:
    id_column = table.c.id
    user_id_column = table.c.user_id
    token_hash_column = table.c.token_hash

    assert isinstance(id_column.type, PostgreSQLUUID)
    assert id_column.type.as_uuid is True
    assert id_column.primary_key is True
    assert id_column.nullable is False
    assert id_column.server_default is None

    assert isinstance(user_id_column.type, PostgreSQLUUID)
    assert user_id_column.type.as_uuid is True
    assert user_id_column.nullable is False

    primary_key = next(
        constraint
        for constraint in table.constraints
        if isinstance(constraint, PrimaryKeyConstraint)
    )
    foreign_key = next(
        constraint
        for constraint in table.constraints
        if isinstance(constraint, ForeignKeyConstraint)
    )
    token_hash_unique = next(
        constraint
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    )

    assert primary_key.name == primary_key_name
    assert {column.name for column in primary_key.columns} == {"id"}
    assert foreign_key.name == foreign_key_name
    assert {column.name for column in foreign_key.columns} == {"user_id"}
    assert {element.target_fullname for element in foreign_key.elements} == {"users.id"}
    assert foreign_key.ondelete == "CASCADE"
    assert token_hash_unique.name == unique_name
    assert {column.name for column in token_hash_unique.columns} == {"token_hash"}

    assert isinstance(token_hash_column.type, String)
    assert token_hash_column.type.length == 255
    assert token_hash_column.nullable is False


def _assert_required_timestamp(table: Table, column_name: str) -> None:
    column = table.c[column_name]
    assert isinstance(column.type, DateTime)
    assert column.type.timezone is True
    assert column.nullable is False


def test_token_models_use_shared_metadata_and_exact_columns() -> None:
    assert User.__table__.metadata is Base.metadata
    assert RefreshToken.__table__.name == "refresh_tokens"
    assert RefreshToken.__table__.metadata is Base.metadata
    assert set(RefreshToken.__table__.columns.keys()) == REFRESH_TOKEN_COLUMNS
    assert PasswordResetToken.__table__.name == "password_reset_tokens"
    assert PasswordResetToken.__table__.metadata is Base.metadata
    assert set(PasswordResetToken.__table__.columns.keys()) == PASSWORD_RESET_TOKEN_COLUMNS


def test_refresh_token_identity_and_token_hash_constraints() -> None:
    _assert_identity_constraints(
        RefreshToken.__table__,
        "pk_refresh_tokens",
        "fk_refresh_tokens_user_id_users",
        "uq_refresh_tokens_token_hash",
    )


def test_refresh_token_expiration_and_revocation_columns() -> None:
    table = RefreshToken.__table__
    _assert_required_timestamp(table, "expires_at")

    is_revoked = table.c.is_revoked
    assert isinstance(is_revoked.type, Boolean)
    assert is_revoked.nullable is False
    assert str(is_revoked.server_default.arg) == "false"

    revoked_at = table.c.revoked_at
    assert isinstance(revoked_at.type, DateTime)
    assert revoked_at.type.timezone is True
    assert revoked_at.nullable is True


def test_refresh_token_client_context_columns() -> None:
    table = RefreshToken.__table__
    assert isinstance(table.c.ip_address.type, INET)
    assert table.c.ip_address.nullable is True
    assert isinstance(table.c.user_agent.type, String)
    assert table.c.user_agent.type.length == 512
    assert table.c.user_agent.nullable is True


def test_refresh_token_created_at_database_default() -> None:
    table = RefreshToken.__table__
    _assert_required_timestamp(table, "created_at")
    assert str(table.c.created_at.server_default.arg) == "CURRENT_TIMESTAMP"


def test_password_reset_token_identity_and_token_hash_constraints() -> None:
    _assert_identity_constraints(
        PasswordResetToken.__table__,
        "pk_password_reset_tokens",
        "fk_password_reset_tokens_user_id_users",
        "uq_password_reset_tokens_token_hash",
    )


def test_password_reset_token_state_and_timestamps() -> None:
    table = PasswordResetToken.__table__
    _assert_required_timestamp(table, "expires_at")
    _assert_required_timestamp(table, "created_at")

    is_used = table.c.is_used
    assert isinstance(is_used.type, Boolean)
    assert is_used.nullable is False
    assert str(is_used.server_default.arg) == "false"
    assert str(table.c.created_at.server_default.arg) == "CURRENT_TIMESTAMP"

"""Structural tests for the token tables Alembic migration."""

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import call, patch

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKeyConstraint,
    MetaData,
    PrimaryKeyConstraint,
    String,
    Table,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID


MIGRATION_PATH = Path("alembic/versions/002_create_token_tables.py")


def load_migration() -> ModuleType:
    """Load migration 002 directly from its stable repository path."""
    spec = importlib.util.spec_from_file_location("token_tables_migration", MIGRATION_PATH)
    assert spec is not None
    assert spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    return migration


def _build_migration_tables(create_table_calls: list[Any]) -> dict[str, Table]:
    metadata = MetaData()
    Table("users", metadata, Column("id", PostgreSQLUUID(as_uuid=True), primary_key=True))
    tables: dict[str, Table] = {}
    for create_table_call in create_table_calls:
        table_name, *schema_elements = create_table_call.args
        tables[table_name] = Table(table_name, metadata, *schema_elements)
    return tables


def _assert_identity_constraints(
    table: Table,
    primary_key_name: str,
    foreign_key_name: str,
    unique_name: str,
) -> None:
    assert isinstance(table.c.id.type, PostgreSQLUUID)
    assert table.c.id.type.as_uuid is True
    assert table.c.id.server_default is None
    assert isinstance(table.c.user_id.type, PostgreSQLUUID)
    assert table.c.user_id.nullable is False
    assert isinstance(table.c.token_hash.type, String)
    assert table.c.token_hash.type.length == 255
    assert table.c.token_hash.nullable is False

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
    unique = next(
        constraint
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    )

    assert primary_key.name == primary_key_name
    assert {column.name for column in primary_key.columns} == {"id"}
    assert foreign_key.name == foreign_key_name
    assert {element.target_fullname for element in foreign_key.elements} == {"users.id"}
    assert foreign_key.ondelete == "CASCADE"
    assert unique.name == unique_name
    assert {column.name for column in unique.columns} == {"token_hash"}


def _assert_timestamp(table: Table, column_name: str, nullable: bool) -> None:
    column = table.c[column_name]
    assert isinstance(column.type, DateTime)
    assert column.type.timezone is True
    assert column.nullable is nullable


def test_token_migration_is_alembic_head_after_users() -> None:
    migration = load_migration()
    script = ScriptDirectory.from_config(Config("alembic.ini"))

    assert migration.revision == "002"
    assert migration.down_revision == "001"
    assert script.get_current_head() == "002"
    assert callable(migration.upgrade)
    assert callable(migration.downgrade)


def test_upgrade_creates_exact_token_tables_and_constraints() -> None:
    migration = load_migration()

    with patch.object(migration.op, "create_table") as create_table:
        migration.upgrade()

    assert create_table.call_count == 2
    tables = _build_migration_tables(create_table.call_args_list)
    assert set(tables) == {"refresh_tokens", "password_reset_tokens"}

    refresh_tokens = tables["refresh_tokens"]
    assert set(refresh_tokens.columns.keys()) == {
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
    _assert_identity_constraints(
        refresh_tokens,
        "pk_refresh_tokens",
        "fk_refresh_tokens_user_id_users",
        "uq_refresh_tokens_token_hash",
    )
    _assert_timestamp(refresh_tokens, "expires_at", False)
    _assert_timestamp(refresh_tokens, "revoked_at", True)
    _assert_timestamp(refresh_tokens, "created_at", False)
    assert isinstance(refresh_tokens.c.is_revoked.type, Boolean)
    assert refresh_tokens.c.is_revoked.nullable is False
    assert str(refresh_tokens.c.is_revoked.server_default.arg) == "false"
    assert isinstance(refresh_tokens.c.ip_address.type, INET)
    assert refresh_tokens.c.ip_address.nullable is True
    assert isinstance(refresh_tokens.c.user_agent.type, String)
    assert refresh_tokens.c.user_agent.type.length == 512
    assert refresh_tokens.c.user_agent.nullable is True
    assert str(refresh_tokens.c.created_at.server_default.arg) == "CURRENT_TIMESTAMP"

    password_reset_tokens = tables["password_reset_tokens"]
    assert set(password_reset_tokens.columns.keys()) == {
        "id",
        "user_id",
        "token_hash",
        "expires_at",
        "is_used",
        "created_at",
    }
    _assert_identity_constraints(
        password_reset_tokens,
        "pk_password_reset_tokens",
        "fk_password_reset_tokens_user_id_users",
        "uq_password_reset_tokens_token_hash",
    )
    _assert_timestamp(password_reset_tokens, "expires_at", False)
    _assert_timestamp(password_reset_tokens, "created_at", False)
    assert isinstance(password_reset_tokens.c.is_used.type, Boolean)
    assert password_reset_tokens.c.is_used.nullable is False
    assert str(password_reset_tokens.c.is_used.server_default.arg) == "false"
    assert str(password_reset_tokens.c.created_at.server_default.arg) == "CURRENT_TIMESTAMP"


def test_downgrade_removes_only_token_tables_in_dependency_safe_order() -> None:
    migration = load_migration()

    with patch.object(migration.op, "drop_table") as drop_table:
        migration.downgrade()

    assert drop_table.mock_calls == [
        call("password_reset_tokens"),
        call("refresh_tokens"),
    ]

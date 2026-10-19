"""Structural tests for the initial users Alembic migration."""

import importlib.util
import os
from pathlib import Path
from types import ModuleType
from unittest.mock import call, patch

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import CheckConstraint, MetaData, Table, UniqueConstraint


os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://test_user:test_password@localhost:5432/db_auth",
)
os.environ.setdefault("DB_ECHO", "false")
os.environ.setdefault("APP_ENV", "test")

from src.models.user import User


MIGRATION_PATH = Path("alembic/versions/001_create_users_table.py")


def load_migration() -> ModuleType:
    """Load the migration module directly from its stable repository path."""
    spec = importlib.util.spec_from_file_location("users_initial_migration", MIGRATION_PATH)
    assert spec is not None
    assert spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    return migration


def test_initial_migration_is_alembic_head() -> None:
    migration = load_migration()
    script = ScriptDirectory.from_config(Config("alembic.ini"))

    assert migration.revision == "001"
    assert migration.down_revision is None
    assert script.get_current_head() == "001"
    assert callable(migration.upgrade)
    assert callable(migration.downgrade)


def test_upgrade_creates_users_schema_matching_model() -> None:
    migration = load_migration()

    with (
        patch.object(migration.op, "create_table") as create_table,
        patch.object(migration.op, "create_index") as create_index,
    ):
        migration.upgrade()

    create_table.assert_called_once()
    table_name, *schema_elements = create_table.call_args.args
    migration_table = Table(table_name, MetaData(), *schema_elements)

    assert migration_table.name == "users"
    assert set(migration_table.columns.keys()) == set(User.__table__.columns.keys())

    role_check = next(
        constraint
        for constraint in migration_table.constraints
        if isinstance(constraint, CheckConstraint)
    )
    email_unique = next(
        constraint
        for constraint in migration_table.constraints
        if isinstance(constraint, UniqueConstraint)
    )

    assert role_check.name == "ck_users_role"
    assert str(role_check.sqltext) == "role IN ('STUDENT', 'COMPANY', 'ADMIN')"
    assert email_unique.name == "uq_users_email"
    assert {column.name for column in email_unique.columns} == {"email"}
    create_index.assert_called_once_with(
        "ix_users_email",
        "users",
        ["email"],
        unique=False,
    )


def test_downgrade_removes_index_then_users_table() -> None:
    migration = load_migration()

    with (
        patch.object(migration.op, "drop_index") as drop_index,
        patch.object(migration.op, "drop_table") as drop_table,
    ):
        migration.downgrade()

    assert drop_index.mock_calls == [call("ix_users_email", table_name="users")]
    assert drop_table.mock_calls == [call("users")]

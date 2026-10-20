"""Unit tests for asynchronous database configuration and sessions."""

import os
from unittest.mock import patch

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession


TEST_DATABASE_URL = "postgresql+asyncpg://test_user:test_password@localhost:5432/db_auth"

# Database settings are intentionally required, so establish safe, non-production
# values before importing the module-level settings and engine objects.
os.environ.setdefault("DATABASE_URL", TEST_DATABASE_URL)
os.environ.setdefault("DB_ECHO", "false")
os.environ.setdefault("APP_ENV", "test")

from src.core.config import Settings
from src.core.database import async_engine, async_session_factory, get_db


def test_settings_load_required_environment_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", TEST_DATABASE_URL)
    monkeypatch.setenv("DB_ECHO", "true")
    monkeypatch.setenv("APP_ENV", "testing")

    loaded_settings = Settings(_env_file=None)

    assert loaded_settings.database_url == TEST_DATABASE_URL
    assert loaded_settings.db_echo is True
    assert loaded_settings.app_env == "testing"


def test_async_engine_uses_postgresql_asyncpg() -> None:
    assert isinstance(async_engine, AsyncEngine)
    assert async_engine.dialect.name == "postgresql"
    assert async_engine.dialect.driver == "asyncpg"


def test_async_engine_pool_configuration() -> None:
    assert async_engine.pool.size() == 10
    assert async_engine.pool._max_overflow == 20
    assert async_engine.pool._pre_ping is True


@pytest.mark.asyncio
async def test_async_session_factory_creates_async_sessions() -> None:
    session = async_session_factory()

    try:
        assert isinstance(session, AsyncSession)
        assert session.sync_session.expire_on_commit is False
    finally:
        await session.close()


@pytest.mark.asyncio
async def test_get_db_yields_and_closes_async_session() -> None:
    session = async_session_factory()

    with (
        patch("src.core.database.async_session_factory", return_value=session),
        patch.object(session, "close", wraps=session.close) as close_session,
    ):
        dependency = get_db()
        yielded_session = await anext(dependency)

        assert yielded_session is session
        assert isinstance(yielded_session, AsyncSession)

        await dependency.aclose()

    close_session.assert_awaited_once_with()

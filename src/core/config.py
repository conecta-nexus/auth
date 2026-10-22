"""Environment-backed application configuration."""

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Database settings loaded from environment variables or a local .env file."""

    database_url: str = Field(
        default="postgresql+asyncpg://postgres:postgrespassword@localhost:5432/db_auth",
        validation_alias="DATABASE_URL",
    )
    db_echo: bool = Field(default=False, validation_alias="DB_ECHO")
    app_env: str = Field(default="development", validation_alias="APP_ENV")

    @field_validator("database_url", mode="before")
    @classmethod
    def normalize_database_url(cls, v: str) -> str:
        """Ensure PostgreSQL connection URLs use the asyncpg async driver."""
        if isinstance(v, str):
            if v.startswith("postgresql://"):
                return v.replace("postgresql://", "postgresql+asyncpg://", 1)
            if v.startswith("postgres://"):
                return v.replace("postgres://", "postgresql+asyncpg://", 1)
        return v

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()


"""Environment-backed application configuration."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Database settings loaded from environment variables or a local .env file."""

    database_url: str = Field(validation_alias="DATABASE_URL")
    db_echo: bool = Field(validation_alias="DB_ECHO")
    app_env: str = Field(validation_alias="APP_ENV")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()

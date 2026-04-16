from __future__ import annotations
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://user:pass@localhost/base_id?ssl=require"
    secret_key: str = "change-me-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 30

    resend_api_key: str = ""
    email_from: str = "noreply@example.com"
    email_from_name: str = "Base ID"

    base_url: str = "http://localhost:8001"
    app_name: str = "Base ID"
    admin_email: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

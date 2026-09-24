"""Application settings loaded from environment variables / .env."""

from functools import lru_cache

from pydantic import Field, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    vt_api_key: str = Field(..., min_length=1, validation_alias="VT_API_KEY")
    cache_ttl_seconds: int = Field(default=600, validation_alias="CACHE_TTL_SECONDS")


@lru_cache
def get_settings() -> Settings:
    try:
        return Settings()
    except ValidationError as exc:
        raise RuntimeError(
            "VT_API_KEY is missing or empty. Set it in your environment or in "
            "a .env file (see .env.example)."
        ) from exc

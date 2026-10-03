from functools import lru_cache
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    """All runtime configuration comes from the environment (.env in development)."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    secret_key: str = Field(min_length=32)
    access_token_expire_minutes: int = 60
    cookie_secure: bool = False
    frontend_origin: str = "http://localhost:3000"

    llm_provider: str = "anthropic"
    llm_api_key: str = ""
    llm_model: str = ""

    zap_url: str = "http://zap:8080"
    zap_api_key: str = ""
    nuclei_path: str = "nuclei"

    max_scan_duration: int = Field(1800, gt=0)
    scan_timeout: int = Field(30, gt=0)
    max_concurrent_scans: int = Field(2, gt=0)
    max_targets_per_user: int = Field(20, gt=0)
    max_crawl_pages: int = Field(200, gt=0)
    max_crawl_depth: int = Field(3, ge=0)
    requests_per_second: float = Field(5, gt=0)

    allow_private_targets: bool = False
    target_allowlist: Annotated[list[str], NoDecode] = []

    demo_mode: bool = False
    reports_dir: str = "reports"

    @field_validator("target_allowlist", mode="before")
    @classmethod
    def _split_csv(cls, v: object) -> object:
        if isinstance(v, str):
            return [h.strip().lower() for h in v.split(",") if h.strip()]
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()

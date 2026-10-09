"""`.env.example` must list exactly the settings the application reads, so a fresh clone that
copies it gets a complete, valid configuration."""

from __future__ import annotations

import re
from pathlib import Path

from app.core.config import Settings

ENV_EXAMPLE = Path(__file__).resolve().parents[2] / ".env.example"
# Read by docker-compose / Next.js rather than by the Settings class.
NON_SETTINGS = {"POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB", "BACKEND_URL"}


def _env_keys() -> set[str]:
    return set(re.findall(r"^([A-Z][A-Z0-9_]*)=", ENV_EXAMPLE.read_text(encoding="utf-8"), re.M))


def test_every_setting_is_documented_in_env_example() -> None:
    settings = {name.upper() for name in Settings.model_fields}
    assert settings - _env_keys() == set(), "add these to .env.example"


def test_env_example_has_no_unknown_keys() -> None:
    settings = {name.upper() for name in Settings.model_fields}
    assert _env_keys() - settings - NON_SETTINGS == set(), "stale keys in .env.example"


def test_env_example_secrets_are_empty_or_explicit_placeholders() -> None:
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    placeholder = re.compile(r"^(|change-me|generate-[a-z0-9-]+)$")
    for key in ("SECRET_KEY", "LLM_API_KEY", "ZAP_API_KEY", "POSTGRES_PASSWORD"):
        value = re.search(rf"^{key}=(.*)$", text, re.M).group(1).strip()
        assert placeholder.match(value), f"{key} in .env.example must be empty or a placeholder"

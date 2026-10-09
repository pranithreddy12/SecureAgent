"""Bundled demo assets for `secureagent demo`."""

from pathlib import Path


def sample_app_path() -> Path:
    """Directory of the deliberately vulnerable sample application."""
    return Path(__file__).parent / "demo_fixtures" / "vulnerable_shop"

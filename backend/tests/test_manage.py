"""Admin bootstrap command."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import UserRole
from app.core.security import verify_password
from app.manage import PASSWORD_ENV, _read_password, create_admin
from app.models import User

pytestmark = pytest.mark.anyio


async def test_creates_a_new_admin_with_a_hashed_password(db_session: AsyncSession) -> None:
    assert await create_admin(db_session, "Root", "Root@Example.com", "correct-horse-battery") == (
        "created"
    )
    user = await db_session.scalar(select(User).where(User.email == "root@example.com"))
    assert user is not None and user.role is UserRole.ADMIN
    assert user.password_hash != "correct-horse-battery"
    assert verify_password("correct-horse-battery", user.password_hash)


async def test_promotes_existing_user_without_touching_password(db_session: AsyncSession) -> None:
    db_session.add(User(name="U", email="u@example.com", password_hash="existing-hash"))
    await db_session.flush()
    assert await create_admin(db_session, "U", "u@example.com", None) == "promoted"
    user = await db_session.scalar(select(User).where(User.email == "u@example.com"))
    assert user.role is UserRole.ADMIN and user.password_hash == "existing-hash"
    assert await create_admin(db_session, "U", "u@example.com", None) == "already-admin"


async def test_new_account_needs_a_valid_password(db_session: AsyncSession) -> None:
    with pytest.raises(ValueError):
        await create_admin(db_session, "A", "a@example.com", None)
    with pytest.raises(ValidationError):
        await create_admin(db_session, "A", "a@example.com", "short")
    with pytest.raises(ValidationError):
        await create_admin(db_session, "A", "not-an-email", "correct-horse-battery")


def test_password_comes_from_the_environment_not_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(PASSWORD_ENV, "from-the-environment-1")
    assert _read_password() == "from-the-environment-1"
    monkeypatch.delenv(PASSWORD_ENV)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert _read_password() is None  # non-interactive and no env var: never invents one

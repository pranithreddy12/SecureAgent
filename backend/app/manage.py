"""Operator commands that need the database (kept out of the dependency-light ``secureagent`` CLI).

    python -m app.manage create-admin --email you@example.com --name "Your Name"

The password is read from ``SECUREAGENT_ADMIN_PASSWORD`` or prompted for; it is never accepted as a
command-line argument (it would land in shell history and process listings). If the account already
exists it is promoted to admin and its password is left unchanged.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import UserRole
from app.core.security import hash_password
from app.models import User
from app.schemas.auth import RegisterRequest

PASSWORD_ENV = "SECUREAGENT_ADMIN_PASSWORD"  # noqa: S105 - name of an env var, not a secret


async def create_admin(db: AsyncSession, name: str, email: str, password: str | None) -> str:
    """Create an admin, or promote the existing user with this email. Returns what happened."""
    email = email.lower()
    existing = await db.scalar(select(User).where(User.email == email))
    if existing is not None:
        if existing.role is UserRole.ADMIN:
            return "already-admin"
        existing.role = UserRole.ADMIN
        await db.commit()
        return "promoted"
    if not password:
        raise ValueError("a password is required to create a new account")
    data = RegisterRequest(name=name, email=email, password=password)  # validates all fields
    db.add(
        User(
            name=data.name,
            email=data.email.lower(),
            password_hash=hash_password(data.password),
            role=UserRole.ADMIN,
        )
    )
    await db.commit()
    return "created"


def _read_password(confirm: bool = True) -> str | None:
    from_env = os.environ.get(PASSWORD_ENV)
    if from_env:
        return from_env
    if not sys.stdin.isatty():
        return None
    first = getpass.getpass("Password: ")
    if confirm and getpass.getpass("Repeat password: ") != first:
        raise ValueError("passwords do not match")
    return first


async def _run(args: argparse.Namespace) -> int:
    from app.core.database import get_sessionmaker

    try:
        async with get_sessionmaker()() as db:
            existing = await db.scalar(select(User).where(User.email == args.email.lower()))
            password = None if existing else _read_password()
            outcome = await create_admin(db, args.name, args.email, password)
    except (ValueError, ValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        {
            "created": f"Created admin {args.email}.",
            "promoted": f"Promoted existing user {args.email} to admin.",
            "already-admin": f"{args.email} is already an admin.",
        }[outcome]
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.manage", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    admin = sub.add_parser("create-admin", help="Create (or promote) an administrator account.")
    admin.add_argument("--email", required=True)
    admin.add_argument("--name", default="Administrator")
    args = parser.parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())

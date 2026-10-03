from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password, verify_password
from app.models import User
from app.schemas.auth import RegisterRequest


class EmailAlreadyRegistered(Exception):
    pass


async def create_user(db: AsyncSession, data: RegisterRequest) -> User:
    user = User(
        name=data.name,
        email=data.email.lower(),
        password_hash=hash_password(data.password),
    )
    db.add(user)
    try:
        await db.commit()
    except IntegrityError as exc:  # unique index on email
        await db.rollback()
        raise EmailAlreadyRegistered from exc
    return user


async def authenticate(db: AsyncSession, email: str, password: str) -> User | None:
    user = await db.scalar(select(User).where(User.email == email.lower()))
    # verify_password always runs (dummy hash when user is None) to avoid a timing oracle.
    if not verify_password(password, user.password_hash if user else None):
        return None
    return user

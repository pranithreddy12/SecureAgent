import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, str_enum, timestamp_col, uuid_pk
from app.models.enums import UserRole

if TYPE_CHECKING:
    from app.models.target import Target


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(120))
    # Lower-cased by the service layer; the unique index enforces one account per email.
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(
        str_enum(UserRole, "user_role"), default=UserRole.AUDITOR, server_default="auditor"
    )
    created_at: Mapped[datetime] = timestamp_col()

    targets: Mapped[list["Target"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )

"""source projects, authorization trail, audits.source_project_id

Revision ID: c8d2e4f6a1b3
Revises: b7c1d2e3f4a5
Create Date: 2026-10-11 15:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c8d2e4f6a1b3"
down_revision: str | Sequence[str] | None = "b7c1d2e3f4a5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "source_projects",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("path", sa.String(length=1024), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("authorization_confirmed", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("authorization_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_source_projects_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_source_projects")),
        sa.UniqueConstraint("user_id", "path", name="uq_source_projects_user_id_path"),
    )
    op.create_index(op.f("ix_source_projects_user_id"), "source_projects", ["user_id"])

    op.create_table(
        "source_authorizations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("confirmed", sa.Boolean(), nullable=False),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column(
            "timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["source_projects.id"],
            name=op.f("fk_source_authorizations_project_id_source_projects"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_source_authorizations_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_source_authorizations")),
    )
    op.create_index(
        op.f("ix_source_authorizations_project_id"), "source_authorizations", ["project_id"]
    )

    op.add_column("security_audits", sa.Column("source_project_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        op.f("fk_security_audits_source_project_id_source_projects"),
        "security_audits",
        "source_projects",
        ["source_project_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        op.f("ix_security_audits_source_project_id"), "security_audits", ["source_project_id"]
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_security_audits_source_project_id"), table_name="security_audits")
    op.drop_constraint(
        op.f("fk_security_audits_source_project_id_source_projects"),
        "security_audits",
        type_="foreignkey",
    )
    op.drop_column("security_audits", "source_project_id")
    op.drop_index(op.f("ix_source_authorizations_project_id"), table_name="source_authorizations")
    op.drop_table("source_authorizations")
    op.drop_index(op.f("ix_source_projects_user_id"), table_name="source_projects")
    op.drop_table("source_projects")

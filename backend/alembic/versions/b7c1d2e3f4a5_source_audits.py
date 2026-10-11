"""source audits: nullable target, audit_type, source and authorization columns

Revision ID: b7c1d2e3f4a5
Revises: afb3ff51caae
Create Date: 2026-10-11 09:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b7c1d2e3f4a5"
down_revision: str | Sequence[str] | None = "afb3ff51caae"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "security_audits",
        sa.Column("audit_type", sa.String(length=16), server_default="live", nullable=False),
    )
    op.add_column("security_audits", sa.Column("source_label", sa.String(length=255), nullable=True))
    op.add_column("security_audits", sa.Column("source_path", sa.String(length=1024), nullable=True))
    op.add_column(
        "security_audits", sa.Column("authorization_statement", sa.Text(), nullable=True)
    )
    op.add_column(
        "security_audits",
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.alter_column("security_audits", "target_id", existing_type=sa.Uuid(), nullable=True)
    op.create_check_constraint(
        op.f("ck_security_audits_audit_type_values"),
        "security_audits",
        "audit_type IN ('live', 'source')",
    )
    op.create_check_constraint(
        op.f("ck_security_audits_live_needs_target"),
        "security_audits",
        "audit_type = 'source' OR target_id IS NOT NULL",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_security_audits_live_needs_target"), "security_audits", type_="check")
    op.drop_constraint(op.f("ck_security_audits_audit_type_values"), "security_audits", type_="check")
    op.execute("DELETE FROM security_audits WHERE target_id IS NULL")
    op.alter_column("security_audits", "target_id", existing_type=sa.Uuid(), nullable=False)
    for col in ("authorized_at", "authorization_statement", "source_path", "source_label", "audit_type"):
        op.drop_column("security_audits", col)

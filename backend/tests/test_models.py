import uuid

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    AuditLog,
    AuthorizationRecord,
    Base,
    ReconnaissanceResult,
    SecurityAudit,
    SecurityReport,
    Target,
    User,
    Vulnerability,
)
from app.models.enums import AuditStatus, FindingStatus, Severity, TargetStatus, UserRole

pytestmark = pytest.mark.anyio


async def make_audit(s: AsyncSession, email: str = "a@example.com") -> SecurityAudit:
    user = User(id=uuid.uuid4(), name="Alice", email=email, password_hash="x")
    target = Target(user=user, name="Shop", url="https://shop.example.com")
    audit = SecurityAudit(target=target, user_id=user.id)
    s.add_all([user, target, audit])
    await s.flush()
    return audit


def vuln(audit: SecurityAudit, fingerprint: str = "f" * 64, **kw) -> Vulnerability:
    fields = dict(
        audit_id=audit.id,
        fingerprint=fingerprint,
        title="Missing CSP header",
        type="security_misconfiguration",
        endpoint="https://shop.example.com/",
        severity=Severity.LOW,
        confidence=0.9,
        status=FindingStatus.CONFIRMED,
    )
    fields.update(kw)
    return Vulnerability(**fields)


async def test_migration_creates_every_model_table(db_session: AsyncSession) -> None:
    rows = await db_session.execute(
        text("select tablename from pg_tables where schemaname = 'public'")
    )
    assert set(Base.metadata.tables) <= {r[0] for r in rows}


async def test_full_audit_graph_round_trip(db_session: AsyncSession) -> None:
    audit = await make_audit(db_session)
    db_session.add_all(
        [
            AuthorizationRecord(
                target_id=audit.target_id,
                user_id=audit.user_id,
                confirmed=True,
                statement="I confirm that I am authorized...",
                scope={"allowed_hosts": ["shop.example.com"]},
            ),
            ReconnaissanceResult(audit_id=audit.id, technologies=["nginx"], endpoints=["/"]),
            vuln(audit, cvss=None, cve=None),
            SecurityReport(audit_id=audit.id, summary="s", report_html="<p>r</p>"),
            AuditLog(audit_id=audit.id, agent="recon", action="start", message="m", meta={"n": 1}),
        ]
    )
    await db_session.flush()
    db_session.expunge_all()

    loaded = await db_session.get(SecurityAudit, audit.id)
    assert loaded is not None
    assert loaded.status is AuditStatus.QUEUED and loaded.progress == 0
    stored = await db_session.scalar(
        text("select status from vulnerabilities where audit_id = :a"), {"a": audit.id}
    )
    assert stored == "confirmed"  # enum *value* stored, not the Python name
    user = await db_session.get(User, audit.user_id)
    assert user is not None and user.role is UserRole.AUDITOR
    target = await db_session.get(Target, audit.target_id)
    assert target is not None and target.status is TargetStatus.PENDING
    log = await db_session.scalar(select(AuditLog).where(AuditLog.audit_id == audit.id))
    assert log is not None and log.meta == {"n": 1}


async def test_duplicate_finding_fingerprint_rejected(db_session: AsyncSession) -> None:
    audit = await make_audit(db_session)
    db_session.add(vuln(audit))
    await db_session.flush()
    db_session.add(vuln(audit))
    with pytest.raises(IntegrityError):
        await db_session.flush()


async def test_duplicate_email_rejected(db_session: AsyncSession) -> None:
    db_session.add(User(name="A", email="dup@example.com", password_hash="x"))
    await db_session.flush()
    db_session.add(User(name="B", email="dup@example.com", password_hash="x"))
    with pytest.raises(IntegrityError):
        await db_session.flush()


@pytest.mark.parametrize(
    "sql",
    [
        "update security_audits set progress = 101",
        "update security_audits set status = 'hacked'",
        "update vulnerabilities set confidence = 1.5",
        "update vulnerabilities set severity = 'catastrophic'",
    ],
)
async def test_check_constraints(db_session: AsyncSession, sql: str) -> None:
    audit = await make_audit(db_session)
    db_session.add(vuln(audit))
    await db_session.flush()
    with pytest.raises(IntegrityError):
        async with db_session.begin_nested():
            await db_session.execute(text(sql))


async def test_deleting_user_cascades(db_session: AsyncSession) -> None:
    audit = await make_audit(db_session)
    db_session.add_all(
        [vuln(audit), AuditLog(audit_id=audit.id, agent="a", action="b", message="c")]
    )
    await db_session.flush()
    await db_session.execute(text("delete from users where id = :u"), {"u": audit.user_id})
    for model in (Target, SecurityAudit, Vulnerability, AuditLog):
        assert await db_session.scalar(select(func.count()).select_from(model)) == 0


async def test_unknown_foreign_key_rejected(db_session: AsyncSession) -> None:
    db_session.add(Target(user_id=uuid.uuid4(), name="x", url="https://x.example"))
    with pytest.raises(IntegrityError):
        await db_session.flush()

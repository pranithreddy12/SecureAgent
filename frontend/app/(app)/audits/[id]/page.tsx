"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";

import {
  AuditStatusLabel,
  FindingStatusLabel,
  SEVERITY_ORDER,
  SeverityBadge,
  isActive,
} from "@/components/badges";
import { Card, ErrorMessage } from "@/components/ui";
import { auditService } from "@/services/audits";
import type { AuditDetail, AuditLogEntry, Finding, Severity } from "@/types/api";

const POLL_MS = 2000;
const STAGES = [
  { key: "scan", label: "Analyse source" },
  { key: "persist", label: "Store findings" },
  { key: "report", label: "Generate report" },
];

export default function AuditDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [audit, setAudit] = useState<AuditDetail | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Severity | "all">("all");

  // Poll while the audit is queued/running; stop once it reaches a terminal state.
  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;

    async function tick() {
      try {
        const detail = await auditService.get(id);
        if (cancelled) return;
        setAudit(detail);
        const [f, l] = await Promise.all([auditService.findings(id), auditService.logs(id)]);
        if (cancelled) return;
        setFindings(f);
        setLogs(l);
        if (isActive(detail.status)) timer = setTimeout(tick, POLL_MS);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Could not load the audit");
      }
    }
    tick();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [id]);

  const visible = useMemo(
    () => (filter === "all" ? findings : findings.filter((f) => f.severity === filter)),
    [findings, filter],
  );

  if (error) return <ErrorMessage message={error} />;
  if (!audit) return <p className="text-sm text-muted">Loading…</p>;

  return (
    <div className="flex max-w-5xl flex-col gap-6">
      <header>
        <Link href="/audits" className="text-xs text-muted hover:text-accent">
          ← All audits
        </Link>
        <h1 className="mt-1 text-2xl font-semibold">{audit.source_label ?? "Source audit"}</h1>
        <p className="mt-1 flex items-center gap-3 text-sm text-muted">
          <AuditStatusLabel status={audit.status} />
          <span>Static source analysis</span>
          {audit.is_demo && <span className="text-warning">DEMO</span>}
        </p>
      </header>

      <Card title="Progress">
        <div
          className="h-2 w-full overflow-hidden rounded bg-surface-raised"
          role="progressbar"
          aria-valuenow={audit.progress}
          aria-valuemin={0}
          aria-valuemax={100}
        >
          <div
            className={`h-full ${audit.status === "failed" ? "bg-danger" : "bg-accent"}`}
            style={{ width: `${audit.progress}%` }}
          />
        </div>
        <ol className="mt-4 flex flex-col gap-1 text-sm">
          {STAGES.map(({ key, label }) => {
            const entry = audit.stage_state[key] as { completed_at?: string | null } | undefined;
            const done = Boolean(entry?.completed_at);
            const current = audit.current_stage === key;
            return (
              <li key={key} className={done ? "text-success" : current ? "text-accent" : "text-muted"}>
                {done ? "✓" : current ? "●" : "○"} {label}
              </li>
            );
          })}
        </ol>
        {audit.error_message && (
          <div className="mt-4">
            <ErrorMessage message={audit.error_message} />
          </div>
        )}
      </Card>

      {audit.status === "completed" && (
        <Card title="Report">
          <div className="flex flex-wrap gap-4 text-sm">
            <a
              className="text-accent hover:underline"
              href={auditService.reportUrl(id)}
              target="_blank"
              rel="noopener noreferrer"
            >
              View report
            </a>
            <a className="text-accent hover:underline" href={auditService.reportUrl(id, { download: true })}>
              Download HTML
            </a>
            <a className="text-accent hover:underline" href={auditService.reportUrl(id, { format: "pdf" })}>
              Download PDF
            </a>
          </div>
        </Card>
      )}

      <Card title={`Findings (${audit.total_findings})`}>
        <div className="mb-4 flex flex-wrap gap-2 text-xs">
          <button
            onClick={() => setFilter("all")}
            className={`rounded border px-2 py-1 ${filter === "all" ? "border-accent text-accent" : "border-border text-muted"}`}
          >
            All
          </button>
          {SEVERITY_ORDER.map((s) => (
            <button
              key={s}
              onClick={() => setFilter(s)}
              className={`rounded border px-2 py-1 capitalize ${filter === s ? "border-accent text-accent" : "border-border text-muted"}`}
            >
              {s} ({audit.finding_counts[s] ?? 0})
            </button>
          ))}
        </div>
        {visible.length === 0 ? (
          <p className="text-sm text-muted">
            {isActive(audit.status) ? "Findings will appear when the scan finishes." : "No findings."}
          </p>
        ) : (
          <ul className="flex flex-col gap-3">
            {visible.map((f) => (
              <li key={f.id} className="rounded-lg border border-border">
                <details>
                  <summary className="flex cursor-pointer flex-wrap items-center gap-3 px-4 py-3">
                    <SeverityBadge severity={f.severity} />
                    <span className="text-sm font-medium">{f.title}</span>
                    <span className="font-mono text-xs text-muted">{f.endpoint}</span>
                  </summary>
                  <div className="flex flex-col gap-2 border-t border-border px-4 py-3 text-sm">
                    <FindingStatusLabel status={f.status} />
                    {f.status_reason && <p className="text-muted">{f.status_reason}</p>}
                    {f.description && <p>{f.description}</p>}
                    {f.impact && (
                      <p>
                        <span className="font-semibold">Impact: </span>
                        {f.impact}
                      </p>
                    )}
                    {f.evidence && (
                      <pre className="overflow-x-auto rounded bg-background p-2 font-mono text-xs">
                        {f.evidence}
                      </pre>
                    )}
                    {f.remediation && (
                      <p>
                        <span className="font-semibold">Fix: </span>
                        {f.remediation}
                      </p>
                    )}
                    <p className="text-xs text-muted">
                      {[f.cwe, f.owasp_category, `confidence ${(f.confidence * 100).toFixed(0)}%`]
                        .filter(Boolean)
                        .join(" · ")}
                      {" · "}
                      {f.cve ?? "no specific CVE"} · {f.cvss ? `CVSS ${f.cvss.score}` : "CVSS not determined"}
                    </p>
                  </div>
                </details>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card title="Activity log">
        <ul className="flex flex-col gap-1 font-mono text-xs">
          {logs.map((l) => (
            <li key={l.id} className={l.status === "error" ? "text-danger" : "text-muted"}>
              {new Date(l.timestamp).toLocaleTimeString()} [{l.agent}] {l.action}: {l.message}
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}

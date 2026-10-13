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
import { Button, Card, ErrorMessage } from "@/components/ui";
import { auditService } from "@/services/audits";
import type { AuditDetail, AuditLogEntry, Finding, Severity } from "@/types/api";

const POLL_MS = 2000;
const STAGES = [
  { key: "authorization", label: "Check authorization and scope" },
  { key: "reconnaissance", label: "Map the application" },
  { key: "scanner", label: "Analyse source" },
  { key: "safe_validation", label: "Verify fixes" },
  { key: "validator", label: "Reduce false positives" },
  { key: "ai_validator", label: "AI review of findings (opt-in)" },
  { key: "correlation", label: "Correlate attack chains" },
  { key: "ai_narrative", label: "AI summary (opt-in)" },
  { key: "report", label: "Generate report" },
];

function Triage({
  auditId,
  finding,
  onChange,
}: {
  auditId: string;
  finding: Finding;
  onChange: (f: Finding) => void;
}) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const marked = finding.status === "false_positive";

  async function send(falsePositive: boolean) {
    setErr(null);
    try {
      onChange(
        await auditService.triage(auditId, finding.id, {
          false_positive: falsePositive,
          reason: falsePositive ? reason : undefined,
        }),
      );
      setOpen(false);
      setReason("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Could not save");
    }
  }

  if (marked && finding.status_reason?.startsWith("Marked false positive")) {
    return (
      <div>
        <Button type="button" onClick={() => send(false)}>
          Undo false positive
        </Button>
        {err && <p className="text-xs text-danger">{err}</p>}
      </div>
    );
  }
  if (marked) return null; // marked by a rule or a suppression file, not by the owner
  if (!open) {
    return (
      <Button type="button" onClick={() => setOpen(true)} className="self-start">
        Mark as false positive
      </Button>
    );
  }
  return (
    <div className="flex flex-col gap-2">
      <label className="text-xs font-medium" htmlFor={`reason-${finding.id}`}>
        Why is this not a real issue? (at least 10 characters, kept with the finding)
      </label>
      <input
        id={`reason-${finding.id}`}
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        maxLength={500}
        className="h-9 rounded-sm border border-border bg-background px-3"
      />
      {err && <p className="text-xs text-danger">{err}</p>}
      <div className="flex gap-2">
        <Button type="button" onClick={() => send(true)} disabled={reason.trim().length < 10}>
          Save
        </Button>
        <Button type="button" onClick={() => setOpen(false)}>
          Cancel
        </Button>
      </div>
    </div>
  );
}

export default function AuditDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [audit, setAudit] = useState<AuditDetail | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Severity | "all">("all");
  const [reload, setReload] = useState(0); // bumped by Retry to restart loading/polling
  const [retrying, setRetrying] = useState(false);

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
  }, [id, reload]);

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
          <div className="mt-4 flex flex-col gap-3">
            <ErrorMessage message={audit.error_message} />
            {audit.status === "failed" && (
              <div className="flex flex-wrap gap-3">
                {[
                  { resume: false, label: "Retry audit" },
                  { resume: true, label: "Resume from failed stage" },
                ].map(({ resume, label }) => (
                  <Button
                    key={label}
                    disabled={retrying}
                    onClick={async () => {
                      setRetrying(true);
                      try {
                        await auditService.retry(id, { resume });
                        setError(null);
                        setReload((n) => n + 1);
                      } catch (err) {
                        setError(err instanceof Error ? err.message : "Could not retry the audit");
                      } finally {
                        setRetrying(false);
                      }
                    }}
                  >
                    {retrying ? "Retrying…" : label}
                  </Button>
                ))}
              </div>
            )}
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

      {audit.ai.enabled && (
        <Card title="AI review">
          <p className="text-sm">
            {audit.ai.reviewed} finding(s) reviewed by {audit.ai.model ?? "the configured model"};
            summary {audit.ai.summary_written ? "written by AI" : "not written (deterministic summary used)"}.
          </p>
          <p className="mt-2 text-xs text-muted">
            AI verdicts are unverified second opinions shown beside each finding. They never change a
            finding&apos;s status, severity or the build gate.
          </p>
          {audit.ai.problems.length > 0 && (
            <ul className="mt-2 list-disc pl-5 text-xs text-warning">
              {audit.ai.problems.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          )}
        </Card>
      )}

      {Object.values(audit.application_model).some((v) => v.length > 0) && (
        <Card title="Source reconnaissance">
          <p className="mb-3 text-xs text-muted">
            What the code reveals about the application. Read from source files only; no running
            system was contacted.
          </p>
          <dl className="flex flex-col gap-2 text-sm">
            {[
              ["technologies", "Technologies"],
              ["parameters", "Inputs read"],
              ["outbound_hosts", "Outbound hosts"],
              ["environment_variables", "Environment variables"],
            ].map(([key, label]) =>
              (audit.application_model[key] ?? []).length > 0 ? (
                <div key={key}>
                  <dt className="text-xs uppercase text-muted">{label}</dt>
                  <dd className="font-mono text-xs">{audit.application_model[key].join(", ")}</dd>
                </div>
              ) : null,
            )}
          </dl>
          {audit.validation_notes.length > 0 && (
            <ul className="mt-3 list-disc pl-5 text-xs text-muted">
              {audit.validation_notes.map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          )}
        </Card>
      )}

      {audit.attack_chains.length > 0 && (
        <Card title={`Attack chains (${audit.attack_chains.length})`}>
          <p className="mb-3 text-xs text-muted">
            Findings that combine into a worse outcome than each alone. A chain interprets the
            findings below; it is not an extra finding and never outranks its worst member.
          </p>
          <ul className="flex flex-col gap-3">
            {audit.attack_chains.map((c) => (
              <li key={c.id} className="rounded-sm border border-border">
                <details>
                  <summary className="flex cursor-pointer flex-wrap items-center gap-3 px-4 py-3">
                    <SeverityBadge severity={c.severity} />
                    <span className="text-sm font-medium">{c.title}</span>
                  </summary>
                  <div className="flex flex-col gap-2 border-t border-border px-4 py-3 text-sm">
                    <p>{c.summary}</p>
                    <ol className="list-decimal pl-5 text-muted">
                      {c.steps.map((s) => (
                        <li key={s}>{s}</li>
                      ))}
                    </ol>
                    <ul className="text-xs text-muted">
                      {c.members.map((m) => (
                        <li key={`${m.role}-${m.location}`}>
                          <span className="font-semibold">{m.role}</span> — {m.title}{" "}
                          <span className="font-mono">({m.location})</span>
                        </li>
                      ))}
                    </ul>
                    <p>
                      <span className="font-semibold">Fix first: </span>
                      {c.fix_first}
                    </p>
                    <p className="text-xs text-muted">Assumes: {c.assumptions.join(" ")}</p>
                  </div>
                </details>
              </li>
            ))}
          </ul>
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
              <li key={f.id} className="rounded-sm border border-border">
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
                    {f.ai_review && (
                      <p className="rounded border border-border p-2 text-xs">
                        <span className="font-semibold">
                          AI second opinion ({f.ai_review.model}):{" "}
                          {f.ai_review.verdict.replace("_", " ")} (
                          {(f.ai_review.confidence * 100).toFixed(0)}%)
                        </span>{" "}
                        {f.ai_review.reason}
                        {f.ai_review.quote && (
                          <>
                            <br />
                            <code>{f.ai_review.quote}</code>
                            {!f.ai_review.quote_verified && " (not found in the code that was sent)"}
                          </>
                        )}
                      </p>
                    )}
                    {audit.status === "completed" && (
                      <Triage
                        auditId={audit.id}
                        finding={f}
                        onChange={(u) =>
                          setFindings((list) => list.map((x) => (x.id === u.id ? u : x)))
                        }
                      />
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

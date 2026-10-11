import type { AuditStatus, FindingStatus, Severity } from "@/types/api";

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "bg-sev-critical/15 text-sev-critical border-sev-critical/40",
  high: "bg-sev-high/15 text-sev-high border-sev-high/40",
  medium: "bg-sev-medium/15 text-sev-medium border-sev-medium/40",
  low: "bg-sev-low/15 text-sev-low border-sev-low/40",
  informational: "bg-sev-info/15 text-sev-info border-sev-info/40",
};

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "informational"];

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-block rounded border px-2 py-0.5 text-xs font-semibold uppercase ${SEVERITY_STYLE[severity]}`}
    >
      {severity}
    </span>
  );
}

const STATUS_STYLE: Record<AuditStatus, string> = {
  queued: "text-muted",
  running: "text-accent",
  completed: "text-success",
  failed: "text-danger",
  cancelled: "text-muted",
};

export function AuditStatusLabel({ status }: { status: AuditStatus }) {
  return <span className={`text-sm font-medium capitalize ${STATUS_STYLE[status]}`}>{status}</span>;
}

// Static analysis never produces "confirmed"; the label states what each status really means.
const FINDING_STATUS_LABEL: Record<FindingStatus, string> = {
  confirmed: "Confirmed",
  likely: "Likely",
  suspicious: "Suspicious — needs review",
  informational: "Informational",
  false_positive: "False positive",
};

export function FindingStatusLabel({ status }: { status: FindingStatus }) {
  return <span className="text-xs text-muted">{FINDING_STATUS_LABEL[status]}</span>;
}

export function isActive(status: AuditStatus): boolean {
  return status === "queued" || status === "running";
}

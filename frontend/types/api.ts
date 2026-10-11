// Mirrors backend Pydantic schemas (backend/app/schemas).

export type UserRole = "admin" | "auditor";

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  user: User;
}

export interface Health {
  status: string;
  demo_mode: boolean;
  llm_configured: boolean;
}

export type AuditStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type FindingStatus =
  | "confirmed"
  | "likely"
  | "suspicious"
  | "informational"
  | "false_positive";

export interface Audit {
  id: string;
  audit_type: "source" | "live";
  source_label: string | null;
  status: AuditStatus;
  current_stage: string | null;
  progress: number;
  is_demo: boolean;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  created_at: string;
  authorized_at: string | null;
}

export interface StageEntry {
  started_at?: string;
  completed_at?: string | null;
  error?: string | null;
}

export interface AuditDetail extends Audit {
  stage_state: Record<string, StageEntry | string[]>;
  finding_counts: Partial<Record<Severity, number>>;
  total_findings: number;
}

export interface Finding {
  id: string;
  title: string;
  type: string;
  endpoint: string;
  parameter: string | null;
  severity: Severity;
  confidence: number;
  status: FindingStatus;
  status_reason: string | null;
  description: string | null;
  impact: string | null;
  evidence: string | null;
  owasp_category: string | null;
  cwe: string | null;
  cve: string | null;
  cvss: { score: number; vector?: string | null; version?: string | null } | null;
  remediation: string | null;
  sources: string[];
}

export interface AuditLogEntry {
  id: string;
  agent: string;
  action: string;
  status: "info" | "success" | "warning" | "error";
  message: string;
  timestamp: string;
}

export interface SourceAuditRequest {
  path: string;
  label?: string;
  authorization_confirmed: boolean;
  exclude: string[];
}

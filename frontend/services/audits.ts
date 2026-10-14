import { api } from "@/lib/api";
import type {
  Audit,
  AuditDetail,
  AuditLogEntry,
  Finding,
  SourceAuditRequest,
  SuggestedFix,
} from "@/types/api";

export const auditService = {
  list: () => api<Audit[]>("/audits"),
  get: (id: string) => api<AuditDetail>(`/audits/${id}`),
  findings: (id: string) => api<Finding[]>(`/audits/${id}/findings`),
  logs: (id: string) => api<AuditLogEntry[]>(`/audits/${id}/logs`),
  retry: (id: string, opts: { resume?: boolean } = {}) =>
    api<Audit>(`/audits/${id}/retry${opts.resume ? "?resume=true" : ""}`, { method: "POST" }),
  triage: (auditId: string, findingId: string, body: { false_positive: boolean; reason?: string }) =>
    api<Finding>(`/audits/${auditId}/findings/${findingId}/triage`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  suggestFix: (auditId: string, findingId: string) =>
    api<SuggestedFix>(`/audits/${auditId}/findings/${findingId}/fix`),
  createSource: (body: SourceAuditRequest) =>
    api<Audit>("/audits/source", { method: "POST", body: JSON.stringify(body) }),
  reportUrl: (id: string, opts: { format?: "html" | "pdf"; download?: boolean } = {}) => {
    const q = new URLSearchParams();
    if (opts.format) q.set("format", opts.format);
    if (opts.download) q.set("download", "true");
    const qs = q.toString();
    return `/api/audits/${id}/report${qs ? `?${qs}` : ""}`;
  },
};

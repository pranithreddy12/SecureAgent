import { api } from "@/lib/api";
import type {
  Audit,
  AuditDetail,
  AuditLogEntry,
  Finding,
  SourceAuditRequest,
} from "@/types/api";

export const auditService = {
  list: () => api<Audit[]>("/audits"),
  get: (id: string) => api<AuditDetail>(`/audits/${id}`),
  findings: (id: string) => api<Finding[]>(`/audits/${id}/findings`),
  logs: (id: string) => api<AuditLogEntry[]>(`/audits/${id}/logs`),
  retry: (id: string) => api<Audit>(`/audits/${id}/retry`, { method: "POST" }),
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

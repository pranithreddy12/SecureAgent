import { api } from "@/lib/api";
import type { Audit, AuditReadiness, Target, TargetAuthorization } from "@/types/api";

export const targetService = {
  list: () => api<Target[]>("/targets"),
  get: (id: string) => api<Target>(`/targets/${id}`),
  create: (body: { name: string; url: string; description?: string; path_prefixes?: string[] }) =>
    api<Target>("/targets", { method: "POST", body: JSON.stringify(body) }),
  remove: (id: string) => api<void>(`/targets/${id}`, { method: "DELETE" }),
  revalidate: (id: string) => api<Target>(`/targets/${id}/revalidate`, { method: "POST" }),
  readiness: (id: string) => api<AuditReadiness>(`/targets/${id}/readiness`),
  authorize: (id: string) =>
    api<TargetAuthorization>(`/targets/${id}/authorize`, {
      method: "POST",
      body: JSON.stringify({ confirmed: true }),
    }),
  audits: (id: string) => api<Audit[]>(`/targets/${id}/audits`),
  startAudit: (id: string) => api<Audit>(`/targets/${id}/audits`, { method: "POST" }),
};

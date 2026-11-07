import { api } from "@/lib/api";
import type { Audit, AuditReadiness, Target, TargetAuthorization } from "@/types/api";

/** Two test accounts of the owner's own app (request headers) + URLs of objects owned by A. */
export type AccessCheckInput = {
  user_a: Record<string, string>;
  user_b: Record<string, string>;
  urls: string[];
};

/** "Cookie: a=1" lines -> { Cookie: "a=1" }. Blank lines are ignored. */
export function parseHeaderLines(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const i = line.indexOf(":");
    if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return out;
}

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
  startAudit: (id: string, accessCheck?: AccessCheckInput) =>
    api<Audit>(`/targets/${id}/audits`, {
      method: "POST",
      ...(accessCheck ? { body: JSON.stringify({ access_check: accessCheck }) } : {}),
    }),
};

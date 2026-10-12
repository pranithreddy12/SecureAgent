import { api } from "@/lib/api";
import type { Audit, AuthorizationEntry, Project, ProjectDetail } from "@/types/api";

export const projectService = {
  list: () => api<Project[]>("/projects"),
  get: (id: string) => api<ProjectDetail>(`/projects/${id}`),
  create: (body: { name: string; path: string; description?: string }) =>
    api<Project>("/projects", { method: "POST", body: JSON.stringify(body) }),
  /** Upload a zip archive; the body is the raw file (ADR-019). */
  upload: (name: string, file: File) =>
    api<Project>(`/projects/upload?name=${encodeURIComponent(name)}`, {
      method: "POST",
      body: file,
      headers: { "Content-Type": "application/zip" },
    }),
  authorize: (id: string) =>
    api<AuthorizationEntry>(`/projects/${id}/authorize`, {
      method: "POST",
      body: JSON.stringify({ confirmed: true }),
    }),
  revoke: (id: string) => api<AuthorizationEntry>(`/projects/${id}/revoke`, { method: "POST" }),
  remove: (id: string) => api<void>(`/projects/${id}`, { method: "DELETE" }),
  audits: (id: string) => api<Audit[]>(`/projects/${id}/audits`),
  startAudit: (id: string, exclude: string[], aiReview = false) =>
    api<Audit>(`/projects/${id}/audits`, {
      method: "POST",
      body: JSON.stringify({ exclude, ai_review: aiReview }),
    }),
};

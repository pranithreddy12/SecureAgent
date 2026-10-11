import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { AuditDetail, Finding } from "@/types/api";

const push = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push, replace: vi.fn() }),
  useParams: () => ({ id: "audit-1" }),
}));

vi.mock("next/link", () => ({
  default: ({ href, children }: { href: string; children: React.ReactNode }) => (
    <a href={href}>{children}</a>
  ),
}));

const service = vi.hoisted(() => ({
  list: vi.fn(),
  get: vi.fn(),
  findings: vi.fn(),
  logs: vi.fn(),
  createSource: vi.fn(),
  retry: vi.fn(),
  reportUrl: (id: string) => `/api/audits/${id}/report`,
}));
vi.mock("@/services/audits", () => ({ auditService: service }));

import AuditDetailPage from "./[id]/page";
import AuditsPage from "./page";

const base: AuditDetail = {
  id: "audit-1",
  audit_type: "source",
  source_label: "Shop",
  status: "completed",
  current_stage: null,
  progress: 100,
  is_demo: false,
  started_at: null,
  completed_at: null,
  error_message: null,
  created_at: "2026-10-11T10:00:00Z",
  authorized_at: null,
  stage_state: { scan: { completed_at: "x" }, persist: { completed_at: "x" }, report: { completed_at: "x" } },
  finding_counts: { high: 1 },
  total_findings: 1,
  attack_chains: [],
  application_model: {},
  validation_notes: [],
};

const finding: Finding = {
  id: "f1",
  title: "SQL injection (tainted input → cur.execute)",
  type: "sql_injection",
  endpoint: "app.py:34",
  parameter: null,
  severity: "high",
  confidence: 0.75,
  status: "suspicious",
  status_reason: null,
  description: null,
  impact: "Attacker-controlled SQL.",
  evidence: "cur.execute(...)",
  owasp_category: "A03:2021 Injection",
  cwe: "CWE-89",
  cve: null,
  cvss: null,
  remediation: "Use parameterised queries.",
  sources: [],
};

beforeEach(() => {
  push.mockReset();
  service.list.mockResolvedValue([]);
  service.findings.mockResolvedValue([finding]);
  service.logs.mockResolvedValue([]);
});

describe("AuditDetailPage", () => {
  it("shows findings, honest CVE/CVSS text and report links for a completed audit", async () => {
    service.get.mockResolvedValue(base);
    render(<AuditDetailPage />);
    expect(await screen.findByText("Shop")).toBeInTheDocument();
    expect(await screen.findByText(/SQL injection/)).toBeInTheDocument();
    expect(screen.getByText("View report")).toHaveAttribute("href", "/api/audits/audit-1/report");
    expect(screen.getByText(/no specific CVE/)).toBeInTheDocument();
    expect(screen.getByText(/CVSS not determined/)).toBeInTheDocument();
  });

  it("shows the static reconnaissance model and the validation notes", async () => {
    service.get.mockResolvedValue({
      ...base,
      application_model: { technologies: ["Flask"], parameters: ["query:q", "path:order_id"] },
      validation_notes: ["2 finding(s) reclassified as informational by rule 'test_or_example_code'."],
    });
    render(<AuditDetailPage />);
    expect(await screen.findByText("Source reconnaissance")).toBeInTheDocument();
    expect(screen.getByText("query:q, path:order_id")).toBeInTheDocument();
    expect(screen.getByText(/no running\s+system was contacted/)).toBeInTheDocument();
    expect(screen.getByText(/reclassified as informational/)).toBeInTheDocument();
  });

  it("renders attack chains with their fix-first advice and assumptions", async () => {
    service.get.mockResolvedValue({
      ...base,
      attack_chains: [
        {
          id: "chain-1",
          title: "SQL injection reachable without authentication: GET /search",
          severity: "high",
          summary: "GET /search has no visible authorization.",
          steps: ["Send crafted input."],
          members: [
            {
              role: "entry",
              title: "Endpoint without visible authorization",
              type: "missing_function_level_authorization",
              location: "app.py:30",
              severity: "medium",
            },
          ],
          fix_first: "Fix the weakness at app.py:34 first.",
          assumptions: ["No global middleware enforces authentication."],
        },
      ],
    });
    render(<AuditDetailPage />);
    expect(await screen.findByText(/Attack chains \(1\)/)).toBeInTheDocument();
    expect(screen.getByText(/Fix the weakness at app.py:34 first/)).toBeInTheDocument();
    expect(screen.getByText(/No global middleware/)).toBeInTheDocument();
  });

  it("shows the failure message and no report links for a failed audit", async () => {
    service.get.mockResolvedValue({
      ...base,
      status: "failed",
      progress: 60,
      error_message: "The source directory could not be read.",
      total_findings: 0,
    });
    service.findings.mockResolvedValue([]);
    render(<AuditDetailPage />);
    expect(await screen.findByText("The source directory could not be read.")).toBeInTheDocument();
    expect(screen.queryByText("View report")).not.toBeInTheDocument();
  });

  it("offers Retry for a failed audit and reloads after it is accepted", async () => {
    service.get
      .mockResolvedValueOnce({ ...base, status: "failed", progress: 60, error_message: "boom" })
      .mockResolvedValue(base);
    service.retry.mockResolvedValue({ ...base, status: "queued" });
    render(<AuditDetailPage />);
    await userEvent.click(await screen.findByRole("button", { name: /retry audit/i }));
    expect(service.retry).toHaveBeenCalledWith("audit-1");
    await waitFor(() => expect(screen.getByText("completed")).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /retry audit/i })).not.toBeInTheDocument();
  });

  it("keeps polling while the audit is running and stops at a terminal state", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    service.get
      .mockResolvedValueOnce({ ...base, status: "running", progress: 30, current_stage: "scan" })
      .mockResolvedValue(base);
    render(<AuditDetailPage />);
    await screen.findByText("running");
    await vi.advanceTimersByTimeAsync(2100);
    await waitFor(() => expect(screen.getByText("completed")).toBeInTheDocument());
    const calls = service.get.mock.calls.length;
    await vi.advanceTimersByTimeAsync(6000);
    expect(service.get.mock.calls.length).toBe(calls); // no polling after completion
    vi.useRealTimers();
  });
});

describe("AuditsPage", () => {
  it("requires the authorization statement before an audit can start", async () => {
    render(<AuditsPage />);
    const start = await screen.findByRole("button", { name: /start audit/i });
    expect(start).toBeDisabled();
    await userEvent.click(screen.getByRole("checkbox"));
    expect(start).toBeEnabled();
  });

  it("submits the parsed form and opens the new audit", async () => {
    service.createSource.mockResolvedValue({ ...base, id: "new-audit" });
    render(<AuditsPage />);
    await userEvent.type(screen.getByLabelText(/Source directory/), "/workspace/shop");
    await userEvent.type(screen.getByLabelText(/Exclude patterns/), "tests/*, *.min.js");
    await userEvent.click(screen.getByRole("checkbox"));
    await userEvent.click(screen.getByRole("button", { name: /start audit/i }));
    await waitFor(() => expect(push).toHaveBeenCalledWith("/audits/new-audit"));
    expect(service.createSource).toHaveBeenCalledWith({
      path: "/workspace/shop",
      label: undefined,
      authorization_confirmed: true,
      exclude: ["tests/*", "*.min.js"],
    });
  });

  it("shows the server's rejection message", async () => {
    service.createSource.mockRejectedValue(new Error("path is outside the allowed roots"));
    render(<AuditsPage />);
    await userEvent.type(screen.getByLabelText(/Source directory/), "/etc");
    await userEvent.click(screen.getByRole("checkbox"));
    await userEvent.click(screen.getByRole("button", { name: /start audit/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent("outside the allowed roots");
    expect(push).not.toHaveBeenCalled();
  });
});

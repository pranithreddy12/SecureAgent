import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Audit, Project, ProjectDetail } from "@/types/api";

const push = vi.fn();
vi.mock("next/navigation", () => ({ useRouter: () => ({ push, replace: vi.fn() }) }));

const system = vi.hoisted(() => ({ health: vi.fn() }));
vi.mock("@/services/auth", () => ({ systemService: system }));

const service = vi.hoisted(() => ({
  list: vi.fn(),
  get: vi.fn(),
  create: vi.fn(),
  upload: vi.fn(),
  authorize: vi.fn(),
  revoke: vi.fn(),
  remove: vi.fn(),
  audits: vi.fn(),
  startAudit: vi.fn(),
}));
vi.mock("@/services/projects", () => ({ projectService: service }));

import RunPage from "./page";

const project: Project = {
  id: "proj-1",
  name: "Shop",
  path: "/workspace/shop",
  description: null,
  authorization_confirmed: false,
  authorization_timestamp: null,
  created_at: "2026-10-11T10:00:00Z",
};
const detail: ProjectDetail = {
  ...project,
  authorization_statement: "I confirm that I own this source code.",
  authorization_history: [],
  audit_count: 0,
};
const audit: Audit = {
  id: "audit-1",
  audit_type: "source",
  source_label: "Shop",
  status: "queued",
  current_stage: null,
  progress: 0,
  is_demo: false,
  started_at: null,
  completed_at: null,
  error_message: null,
  created_at: "2026-10-11T10:00:00Z",
  authorized_at: null,
};

beforeEach(() => {
  push.mockReset();
  Object.values(service).forEach((fn) => fn.mockReset());
  service.list.mockResolvedValue([project]);
  service.get.mockResolvedValue(detail);
  service.authorize.mockResolvedValue({ confirmed: true, statement: "", timestamp: "" });
  service.startAudit.mockResolvedValue(audit);
  system.health.mockResolvedValue({ status: "ok", demo_mode: false, llm_configured: false });
});

describe("RunPage", () => {
  it("runs an existing, unauthorized project end to end", async () => {
    const user = userEvent.setup();
    render(<RunPage />);

    await user.click(screen.getByRole("button", { name: /a project you already registered/i }));
    await screen.findByRole("combobox");
    await user.selectOptions(screen.getByRole("combobox"), "proj-1");

    await screen.findByText(/I confirm that I own this source code/);
    await user.click(screen.getByRole("checkbox"));
    await user.click(screen.getByRole("button", { name: /run security audit/i }));

    await waitFor(() => expect(service.authorize).toHaveBeenCalledWith("proj-1"));
    expect(service.startAudit).toHaveBeenCalledWith("proj-1", [], false);
    expect(push).toHaveBeenCalledWith("/audits/audit-1");
  });
});

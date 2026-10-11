import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { ProjectDetail } from "@/types/api";

const push = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push, replace: vi.fn() }),
  useParams: () => ({ id: "proj-1" }),
}));

vi.mock("next/link", () => ({
  default: ({ href, children }: { href: string; children: React.ReactNode }) => (
    <a href={href}>{children}</a>
  ),
}));

const service = vi.hoisted(() => ({
  list: vi.fn(),
  get: vi.fn(),
  create: vi.fn(),
  authorize: vi.fn(),
  revoke: vi.fn(),
  remove: vi.fn(),
  audits: vi.fn(),
  startAudit: vi.fn(),
}));
vi.mock("@/services/projects", () => ({ projectService: service }));

import ProjectPage from "./[id]/page";
import ProjectsPage from "./page";

const base: ProjectDetail = {
  id: "proj-1",
  name: "Shop",
  path: "/workspace/shop",
  description: null,
  authorization_confirmed: false,
  authorization_timestamp: null,
  created_at: "2026-10-11T10:00:00Z",
  authorization_statement: "I confirm that I own this source code.",
  authorization_history: [],
  audit_count: 0,
};

beforeEach(() => {
  push.mockReset();
  Object.values(service).forEach((fn) => fn.mockReset());
  service.list.mockResolvedValue([]);
  service.audits.mockResolvedValue([]);
});

describe("ProjectsPage", () => {
  it("lists projects with their authorization state", async () => {
    service.list.mockResolvedValue([
      { ...base, id: "a", name: "Authorized one", authorization_confirmed: true },
      { ...base, id: "b", name: "Pending one" },
    ]);
    render(<ProjectsPage />);
    expect(await screen.findByText("Authorized one")).toBeInTheDocument();
    expect(screen.getByText("Authorized")).toBeInTheDocument();
    expect(screen.getByText("Not authorized")).toBeInTheDocument();
  });

  it("registers a project and opens it", async () => {
    service.create.mockResolvedValue({ ...base, id: "new-id" });
    render(<ProjectsPage />);
    await userEvent.type(screen.getByLabelText("Name"), "Shop");
    await userEvent.type(screen.getByLabelText(/Source directory/), "/workspace/shop");
    await userEvent.click(screen.getByRole("button", { name: /register project/i }));
    await waitFor(() => expect(push).toHaveBeenCalledWith("/projects/new-id"));
    expect(service.create).toHaveBeenCalledWith({
      name: "Shop",
      path: "/workspace/shop",
      description: undefined,
    });
  });

  it("shows the server's rejection", async () => {
    service.create.mockRejectedValue(new Error("path is outside the allowed roots"));
    render(<ProjectsPage />);
    await userEvent.type(screen.getByLabelText("Name"), "x");
    await userEvent.type(screen.getByLabelText(/Source directory/), "/etc");
    await userEvent.click(screen.getByRole("button", { name: /register project/i }));
    expect(await screen.findByText(/outside the allowed roots/)).toBeInTheDocument();
    expect(push).not.toHaveBeenCalled();
  });
});

describe("ProjectPage", () => {
  it("blocks auditing until authorization is confirmed", async () => {
    service.get.mockResolvedValue(base);
    render(<ProjectPage />);
    const start = await screen.findByRole("button", { name: /start audit/i });
    expect(start).toBeDisabled();
    const confirm = screen.getByRole("button", { name: /confirm authorization/i });
    expect(confirm).toBeDisabled();
    await userEvent.click(screen.getByRole("checkbox"));
    expect(confirm).toBeEnabled();
  });

  it("authorizes, then offers revocation and enables audits", async () => {
    service.get
      .mockResolvedValueOnce(base)
      .mockResolvedValue({
        ...base,
        authorization_confirmed: true,
        authorization_timestamp: "2026-10-11T11:00:00Z",
        authorization_history: [
          { confirmed: true, statement: "s", timestamp: "2026-10-11T11:00:00Z" },
        ],
      });
    service.authorize.mockResolvedValue({ confirmed: true, statement: "s", timestamp: "" });
    render(<ProjectPage />);
    await userEvent.click(await screen.findByRole("checkbox"));
    await userEvent.click(screen.getByRole("button", { name: /confirm authorization/i }));
    expect(await screen.findByRole("button", { name: /revoke authorization/i })).toBeInTheDocument();
    expect(service.authorize).toHaveBeenCalledWith("proj-1");
    expect(screen.getByRole("button", { name: /start audit/i })).toBeEnabled();
  });

  it("starts an audit with parsed exclude patterns and opens it", async () => {
    service.get.mockResolvedValue({ ...base, authorization_confirmed: true });
    service.startAudit.mockResolvedValue({ id: "audit-9" });
    render(<ProjectPage />);
    await userEvent.type(await screen.findByLabelText(/Exclude patterns/), "tests/*, *.min.js");
    await userEvent.click(screen.getByRole("button", { name: /start audit/i }));
    await waitFor(() => expect(push).toHaveBeenCalledWith("/audits/audit-9"));
    expect(service.startAudit).toHaveBeenCalledWith("proj-1", ["tests/*", "*.min.js"]);
  });

  it("surfaces a refused audit (e.g. concurrency limit)", async () => {
    service.get.mockResolvedValue({ ...base, authorization_confirmed: true });
    service.startAudit.mockRejectedValue(new Error("Too many audits are already queued or running."));
    render(<ProjectPage />);
    await userEvent.click(await screen.findByRole("button", { name: /start audit/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/Too many audits/);
  });
});

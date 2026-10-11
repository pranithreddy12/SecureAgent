import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  AuditStatusLabel,
  FindingStatusLabel,
  SEVERITY_ORDER,
  SeverityBadge,
  isActive,
} from "./badges";

describe("badges", () => {
  it("orders severities from most to least severe", () => {
    expect(SEVERITY_ORDER).toEqual(["critical", "high", "medium", "low", "informational"]);
  });

  it("renders the severity text", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("critical")).toBeInTheDocument();
  });

  it("spells out what 'suspicious' means instead of implying a confirmed flaw", () => {
    render(<FindingStatusLabel status="suspicious" />);
    expect(screen.getByText(/needs review/i)).toBeInTheDocument();
  });

  it("treats only queued and running as active (polling continues)", () => {
    expect(isActive("queued")).toBe(true);
    expect(isActive("running")).toBe(true);
    expect(isActive("completed")).toBe(false);
    expect(isActive("failed")).toBe(false);
  });

  it("renders the audit status", () => {
    render(<AuditStatusLabel status="failed" />);
    expect(screen.getByText("failed")).toBeInTheDocument();
  });
});

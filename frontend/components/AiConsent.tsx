"use client";

import { useEffect, useState } from "react";

import { systemService } from "@/services/auth";

/** Opt-in for AI review. Rendered only when the server has an LLM key configured. */
export function AiConsent({
  checked,
  onChange,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
}) {
  const [available, setAvailable] = useState(false);

  useEffect(() => {
    systemService.health().then(
      (h) => setAvailable(Boolean(h.llm_configured)),
      () => setAvailable(false),
    );
  }, []);

  if (!available) return null;
  return (
    <label className="flex items-start gap-2 rounded-sm border border-border p-3 text-sm">
      <input
        type="checkbox"
        className="mt-1"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>
        <span className="font-medium">AI review (optional)</span>
        <span className="mt-1 block text-xs text-muted">
          Ask an AI model for a second opinion on the 15 most severe findings and to write the
          summary. This sends excerpts of the affected functions (secrets redacted) to the LLM
          provider configured on this server. The AI never changes a finding&apos;s status or
          the build gate.
        </span>
      </span>
    </label>
  );
}

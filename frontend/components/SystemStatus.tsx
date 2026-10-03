"use client";

import { useEffect, useState } from "react";

import { Card, StatusDot } from "@/components/ui";
import { systemService } from "@/services/auth";
import type { Health } from "@/types/api";

export function SystemStatus() {
  const [health, setHealth] = useState<Health | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    systemService.health().then(setHealth, () => setFailed(true));
  }, []);

  return (
    <Card title="System status">
      {failed ? (
        <StatusDot ok={false} label="Backend unreachable" />
      ) : !health ? (
        <p className="text-sm text-muted">Checking…</p>
      ) : (
        <div className="flex flex-col gap-2">
          <StatusDot ok={health.status === "ok"} label="Backend API online" />
          <StatusDot
            ok={health.llm_configured}
            label={health.llm_configured ? "LLM configured" : "LLM not configured (deterministic mode)"}
          />
          <StatusDot
            ok={!health.demo_mode}
            label={health.demo_mode ? "DEMO MODE enabled" : "Demo mode off"}
          />
        </div>
      )}
    </Card>
  );
}

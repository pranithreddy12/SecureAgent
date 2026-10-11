"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { AuditStatusLabel } from "@/components/badges";
import { SystemStatus } from "@/components/SystemStatus";
import { Card } from "@/components/ui";
import { auditService } from "@/services/audits";
import type { Audit } from "@/types/api";

export default function DashboardPage() {
  const [audits, setAudits] = useState<Audit[] | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    auditService.list().then(setAudits, () => setFailed(true));
  }, []);

  const completed = audits?.filter((a) => a.status === "completed").length ?? 0;
  const running = audits?.filter((a) => a.status === "queued" || a.status === "running").length ?? 0;

  return (
    <div className="flex max-w-5xl flex-col gap-6">
      <header>
        <h1 className="text-2xl font-semibold">Dashboard</h1>
        <p className="mt-1 text-sm text-muted">Security audit overview</p>
      </header>
      <div className="grid gap-4 md:grid-cols-2">
        <SystemStatus />
        <Card title="Audit overview">
          {/* Real counts from the API only; nothing here is simulated. */}
          {failed ? (
            <p className="text-sm text-danger">Could not load audits.</p>
          ) : !audits ? (
            <p className="text-sm text-muted">Loading…</p>
          ) : audits.length === 0 ? (
            <p className="text-sm text-muted">
              No audits yet.{" "}
              <Link href="/audits" className="text-accent hover:underline">
                Start a source audit
              </Link>
              .
            </p>
          ) : (
            <dl className="grid grid-cols-3 gap-2 text-center">
              <div>
                <dt className="text-xs text-muted">Total</dt>
                <dd className="text-2xl font-semibold">{audits.length}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted">Completed</dt>
                <dd className="text-2xl font-semibold text-success">{completed}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted">In progress</dt>
                <dd className="text-2xl font-semibold text-accent">{running}</dd>
              </div>
            </dl>
          )}
        </Card>
      </div>
      {audits && audits.length > 0 && (
        <Card title="Recent audits">
          <ul className="flex flex-col divide-y divide-border text-sm">
            {audits.slice(0, 5).map((a) => (
              <li key={a.id} className="flex items-center justify-between py-2">
                <Link href={`/audits/${a.id}`} className="text-accent hover:underline">
                  {a.source_label ?? a.id.slice(0, 8)}
                </Link>
                <AuditStatusLabel status={a.status} />
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}

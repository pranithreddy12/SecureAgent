"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState, type FormEvent } from "react";

import { AuditStatusLabel } from "@/components/badges";
import { Button, Card, ErrorMessage, Field } from "@/components/ui";
import { auditService } from "@/services/audits";
import type { Audit } from "@/types/api";

const STATEMENT =
  "I confirm that I own this source code or am explicitly authorized to analyse it, and that " +
  "SecureAgent may read it for a security audit.";

export default function AuditsPage() {
  const router = useRouter();
  const [audits, setAudits] = useState<Audit[] | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmed, setConfirmed] = useState(false);

  const load = useCallback(() => {
    auditService.list().then(setAudits, (e) => setListError(e.message));
  }, []);

  useEffect(load, [load]);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const exclude = String(form.get("exclude") ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    setBusy(true);
    setError(null);
    try {
      const audit = await auditService.createSource({
        path: String(form.get("path")),
        label: String(form.get("label") ?? "").trim() || undefined,
        authorization_confirmed: confirmed,
        exclude,
      });
      router.push(`/audits/${audit.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start the audit");
      setBusy(false);
    }
  }

  return (
    <div className="flex max-w-5xl flex-col gap-6">
      <header>
        <h1 className="text-2xl font-semibold">Audits</h1>
        <p className="mt-1 text-sm text-muted">
          Static source-code security audits. Nothing is executed and no network request is made
          to your application.
        </p>
      </header>

      <Card title="New source audit">
        <form onSubmit={onSubmit} className="flex flex-col gap-4">
          <Field
            label="Source directory (on the server)"
            name="path"
            required
            placeholder="/workspace/my-app"
            hint="Must be under the server's SOURCE_ROOTS (docker compose mounts ./workspace at /workspace)."
          />
          <Field label="Label (optional)" name="label" maxLength={255} placeholder="My app" />
          <Field
            label="Exclude patterns (optional)"
            name="exclude"
            placeholder="tests/*, *.min.js"
            hint="Comma-separated globs of files to skip."
          />
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              className="mt-1"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
            />
            <span>{STATEMENT}</span>
          </label>
          <ErrorMessage message={error} />
          <Button type="submit" disabled={busy || !confirmed} className="self-start">
            {busy ? "Starting…" : "Start audit"}
          </Button>
        </form>
      </Card>

      <Card title="History">
        <ErrorMessage message={listError} />
        {!audits && !listError && <p className="text-sm text-muted">Loading…</p>}
        {audits && audits.length === 0 && (
          <p className="text-sm text-muted">No audits yet. Start one above.</p>
        )}
        {audits && audits.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-muted">
                <tr>
                  <th className="py-2 pr-4">Source</th>
                  <th className="py-2 pr-4">Status</th>
                  <th className="py-2 pr-4">Started</th>
                  <th className="py-2">Progress</th>
                </tr>
              </thead>
              <tbody>
                {audits.map((a) => (
                  <tr key={a.id} className="border-t border-border">
                    <td className="py-2 pr-4">
                      <Link href={`/audits/${a.id}`} className="text-accent hover:underline">
                        {a.source_label ?? a.id.slice(0, 8)}
                      </Link>
                    </td>
                    <td className="py-2 pr-4">
                      <AuditStatusLabel status={a.status} />
                    </td>
                    <td className="py-2 pr-4 text-muted">
                      {new Date(a.created_at).toLocaleString()}
                    </td>
                    <td className="py-2 text-muted">{a.progress}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

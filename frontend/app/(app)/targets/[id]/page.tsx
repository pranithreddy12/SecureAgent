"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { AuditStatusLabel } from "@/components/badges";
import { Button, Card, ErrorMessage } from "@/components/ui";
import { parseHeaderLines, targetService } from "@/services/targets";
import type { Audit, Target } from "@/types/api";

const STATUS_STYLE: Record<Target["status"], string> = {
  pending: "text-muted",
  validated: "text-success",
  rejected: "text-danger",
  archived: "text-muted",
};

export default function TargetPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [target, setTarget] = useState<Target | null>(null);
  const [audits, setAudits] = useState<Audit[]>([]);
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [version, setVersion] = useState(0);
  const [headersA, setHeadersA] = useState("");
  const [headersB, setHeadersB] = useState("");
  const [objectUrls, setObjectUrls] = useState("");

  useEffect(() => {
    let cancelled = false;
    Promise.all([targetService.get(id), targetService.audits(id)]).then(
      ([t, a]) => {
        if (cancelled) return;
        setTarget(t);
        setAudits(a);
      },
      (err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Could not load the target");
      },
    );
    return () => {
      cancelled = true;
    };
  }, [id, version]);

  async function run(action: () => Promise<unknown>, after?: () => void) {
    setBusy(true);
    setError(null);
    try {
      await action();
      setVersion((v) => v + 1);
      after?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }

  async function onStart() {
    setBusy(true);
    setError(null);
    try {
      const urls = objectUrls.split(/\r?\n/).map((u) => u.trim()).filter(Boolean);
      const accessCheck = urls.length
        ? { user_a: parseHeaderLines(headersA), user_b: parseHeaderLines(headersB), urls }
        : undefined;
      const audit = await targetService.startAudit(id, accessCheck);
      router.push(`/audits/${audit.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start the audit");
      setBusy(false);
    }
  }

  if (!target) return error ? <ErrorMessage message={error} /> : <p className="text-sm text-muted">Loading…</p>;

  const canRun = target.status === "validated" && target.authorization_confirmed;

  return (
    <div className="flex max-w-5xl flex-col gap-6">
      <header>
        <Link href="/targets" className="text-xs text-muted hover:text-accent">
          ← All targets
        </Link>
        <h1 className="mt-1 text-2xl font-semibold">{target.name}</h1>
        <p className="font-mono text-xs text-muted">{target.url}</p>
        {target.description && <p className="mt-1 text-sm text-muted">{target.description}</p>}
      </header>

      <ErrorMessage message={error} />

      <Card title="Safety validation">
        <p className={`text-sm font-medium capitalize ${STATUS_STYLE[target.status]}`}>
          {target.status}
        </p>
        {target.validation_message && (
          <p className="mt-1 text-sm text-muted">{target.validation_message}</p>
        )}
        <p className="mt-2 text-xs text-muted">
          Checked for private/loopback/cloud-metadata addresses, DNS-resolved, and scope-confined
          to this host. If the target&apos;s DNS or IP has changed since registration, revalidate.
        </p>
        <Button
          className="mt-3 self-start"
          disabled={busy}
          onClick={() => run(() => targetService.revalidate(id))}
        >
          Revalidate
        </Button>
      </Card>

      <Card title="Authorization">
        {target.authorization_confirmed ? (
          <div className="flex flex-col gap-3 text-sm">
            <p className="text-success">
              Authorized
              {target.authorization_timestamp &&
                ` on ${new Date(target.authorization_timestamp).toLocaleString()}`}
              .
            </p>
          </div>
        ) : (
          <div className="flex flex-col gap-3 text-sm">
            <p className="text-warning">Not authorized. Audits cannot start until you confirm.</p>
            <label className="flex items-start gap-2">
              <input
                type="checkbox"
                className="mt-1"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
              />
              <span>I confirm that I am authorized to perform security testing against this target.</span>
            </label>
            <Button
              className="self-start"
              disabled={busy || !confirmed || target.status !== "validated"}
              onClick={() => run(() => targetService.authorize(id), () => setConfirmed(false))}
            >
              Confirm authorization
            </Button>
          </div>
        )}
      </Card>

      <Card title="Run a live audit">
        <p className="mb-3 text-xs text-muted">
          A real, non-destructive scan against this URL: recon, OWASP ZAP + Nuclei (when
          configured on the server) and deterministic passive checks, then a live, non-destructive
          re-fetch to confirm what it finds -- the only audits this product can honestly mark{" "}
          <code>confirmed</code> rather than <code>likely</code>.
        </p>
        <details className="mb-3 text-sm">
          <summary className="cursor-pointer">Cross-account access check (optional)</summary>
          <p className="mt-2 text-xs text-muted">
            Give two test accounts of your own application as request headers, and URLs of
            objects that belong to account A. The audit reads each URL as A, anonymously and as
            B (GET only). If B receives A&apos;s object, object-level authorization is missing and
            the finding is <code>confirmed</code>. Credentials are kept in memory for this run
            only and never stored.
          </p>
          <div className="mt-2 grid gap-2 sm:grid-cols-2">
            <label className="flex flex-col gap-1 text-xs">
              Account A headers (one per line)
              <textarea
                className="rounded border border-border bg-surface p-2 font-mono"
                rows={3}
                placeholder="Cookie: session=..."
                value={headersA}
                onChange={(e) => setHeadersA(e.target.value)}
              />
            </label>
            <label className="flex flex-col gap-1 text-xs">
              Account B headers (one per line)
              <textarea
                className="rounded border border-border bg-surface p-2 font-mono"
                rows={3}
                placeholder="Authorization: Bearer ..."
                value={headersB}
                onChange={(e) => setHeadersB(e.target.value)}
              />
            </label>
          </div>
          <label className="mt-2 flex flex-col gap-1 text-xs">
            URLs of account A&apos;s objects (one per line, max 50)
            <textarea
              className="rounded border border-border bg-surface p-2 font-mono"
              rows={3}
              placeholder={`${target.url.replace(/\/$/, "")}/api/orders/123`}
              value={objectUrls}
              onChange={(e) => setObjectUrls(e.target.value)}
            />
          </label>
        </details>
        <Button className="self-start" disabled={busy || !canRun} onClick={onStart}>
          {busy ? "Starting…" : "Start live audit"}
        </Button>
      </Card>

      <Card title={`Audits (${audits.length})`}>
        {audits.length === 0 ? (
          <p className="text-sm text-muted">No audits for this target yet.</p>
        ) : (
          <ul className="flex flex-col divide-y divide-border text-sm">
            {audits.map((a) => (
              <li key={a.id} className="flex items-center justify-between py-2">
                <Link href={`/audits/${a.id}`} className="text-accent hover:underline">
                  {new Date(a.created_at).toLocaleString()}
                </Link>
                <AuditStatusLabel status={a.status} />
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card title="Danger zone">
        <Button
          disabled={busy}
          className="border-danger/50 bg-danger text-background hover:border-danger hover:bg-danger/80 hover:text-background"
          onClick={() => {
            if (window.confirm("Delete this target? Its audits are kept but unlinked.")) {
              void run(() => targetService.remove(id), () => router.push("/targets"));
            }
          }}
        >
          Delete target
        </Button>
      </Card>
    </div>
  );
}

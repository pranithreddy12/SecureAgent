"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";

import { AuditStatusLabel } from "@/components/badges";
import { Button, Card, ErrorMessage, Field } from "@/components/ui";
import { projectService } from "@/services/projects";
import type { Audit, ProjectDetail } from "@/types/api";

export default function ProjectPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [project, setProject] = useState<ProjectDetail | null>(null);
  const [audits, setAudits] = useState<Audit[]>([]);
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [version, setVersion] = useState(0); // bump to reload after a change

  useEffect(() => {
    let cancelled = false;
    Promise.all([projectService.get(id), projectService.audits(id)]).then(
      ([p, a]) => {
        if (cancelled) return;
        setProject(p);
        setAudits(a);
      },
      (err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Could not load the project");
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

  async function onStart(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const raw = String(new FormData(e.currentTarget).get("exclude") ?? "");
    const exclude = raw
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    setBusy(true);
    setError(null);
    try {
      const audit = await projectService.startAudit(id, exclude);
      router.push(`/audits/${audit.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start the audit");
      setBusy(false);
    }
  }

  if (!project) return error ? <ErrorMessage message={error} /> : <p className="text-sm text-muted">Loading…</p>;

  return (
    <div className="flex max-w-5xl flex-col gap-6">
      <header>
        <Link href="/projects" className="text-xs text-muted hover:text-accent">
          ← All projects
        </Link>
        <h1 className="mt-1 text-2xl font-semibold">{project.name}</h1>
        <p className="font-mono text-xs text-muted">{project.path}</p>
        {project.description && <p className="mt-1 text-sm text-muted">{project.description}</p>}
      </header>

      <ErrorMessage message={error} />

      <Card title="Authorization">
        {project.authorization_confirmed ? (
          <div className="flex flex-col gap-3 text-sm">
            <p className="text-success">
              Authorized
              {project.authorization_timestamp &&
                ` on ${new Date(project.authorization_timestamp).toLocaleString()}`}
              .
            </p>
            <p className="text-muted">{project.authorization_statement}</p>
            <Button
              className="self-start"
              disabled={busy}
              onClick={() => run(() => projectService.revoke(id))}
            >
              Revoke authorization
            </Button>
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
              <span>{project.authorization_statement}</span>
            </label>
            <Button
              className="self-start"
              disabled={busy || !confirmed}
              onClick={() => run(() => projectService.authorize(id), () => setConfirmed(false))}
            >
              Confirm authorization
            </Button>
          </div>
        )}
        {project.authorization_history.length > 0 && (
          <ul className="mt-4 text-xs text-muted">
            {project.authorization_history.map((h) => (
              <li key={h.timestamp + h.confirmed}>
                {new Date(h.timestamp).toLocaleString()} — {h.confirmed ? "confirmed" : "revoked"}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card title="Run an audit">
        <form onSubmit={onStart} className="flex flex-col gap-4">
          <Field
            label="Exclude patterns (optional)"
            name="exclude"
            placeholder="tests/*, *.min.js"
            hint="Comma-separated globs of files to skip."
          />
          <Button
            type="submit"
            className="self-start"
            disabled={busy || !project.authorization_confirmed}
          >
            {busy ? "Starting…" : "Start audit"}
          </Button>
        </form>
      </Card>

      <Card title={`Audits (${audits.length})`}>
        {audits.length === 0 ? (
          <p className="text-sm text-muted">No audits for this project yet.</p>
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
          className="bg-danger text-background hover:bg-danger/80"
          onClick={() => {
            if (window.confirm("Delete this project? Its audits are kept but unlinked.")) {
              void run(() => projectService.remove(id), () => router.push("/projects"));
            }
          }}
        >
          Delete project
        </Button>
      </Card>
    </div>
  );
}

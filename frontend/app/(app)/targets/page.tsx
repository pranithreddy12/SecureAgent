"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";

import { Button, Card, ErrorMessage, Field } from "@/components/ui";
import { targetService } from "@/services/targets";
import type { Target } from "@/types/api";

const STATUS_STYLE: Record<Target["status"], string> = {
  pending: "text-muted",
  validated: "text-success",
  rejected: "text-danger",
  archived: "text-muted",
};

export default function TargetsPage() {
  const router = useRouter();
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    targetService.list().then(setTargets, (e) => setListError(e.message));
  }, []);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      const target = await targetService.create({
        name: String(form.get("name")),
        url: String(form.get("url")),
        description: String(form.get("description") ?? "").trim() || undefined,
      });
      router.push(`/targets/${target.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not register the target");
      setBusy(false);
    }
  }

  return (
    <div className="flex max-w-5xl flex-col gap-6">
      <header>
        <h1 className="text-2xl font-semibold">Targets</h1>
        <p className="mt-1 text-sm text-muted">
          A live URL you are authorized to test. Registering one checks it is not private,
          loopback, cloud metadata or otherwise unsafe before any scan can start -- static source
          audits live on the <Link href="/projects" className="text-accent hover:underline">Projects</Link> page instead.
        </p>
      </header>

      <Card title="Register a target">
        <form onSubmit={onSubmit} className="flex flex-col gap-4">
          <Field label="Name" name="name" required maxLength={120} placeholder="Shop API" />
          <Field
            label="URL"
            name="url"
            type="url"
            required
            placeholder="https://staging.example.com"
            hint="http/https only; no credentials in the URL. Checked for safety on registration, not here."
          />
          <Field label="Description (optional)" name="description" maxLength={2000} />
          <ErrorMessage message={error} />
          <Button type="submit" disabled={busy} className="self-start">
            {busy ? "Registering…" : "Register target"}
          </Button>
        </form>
      </Card>

      <Card title="Your targets">
        <ErrorMessage message={listError} />
        {!targets && !listError && <p className="text-sm text-muted">Loading…</p>}
        {targets && targets.length === 0 && (
          <p className="text-sm text-muted">No targets yet. Register one above.</p>
        )}
        {targets && targets.length > 0 && (
          <ul className="flex flex-col divide-y divide-border text-sm">
            {targets.map((t) => (
              <li key={t.id} className="flex flex-wrap items-center justify-between gap-2 py-3">
                <div>
                  <Link href={`/targets/${t.id}`} className="font-medium text-accent hover:underline">
                    {t.name}
                  </Link>
                  <p className="font-mono text-xs text-muted">{t.url}</p>
                </div>
                <span className={`capitalize ${STATUS_STYLE[t.status]}`}>{t.status}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
